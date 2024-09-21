import encoding.base64
import crypto.hmac
import http
import net
import uuid
import crypto.sha256 show sha256
// import certificate_roots



/**
  Removes any padding on a base64 encoded string.
  Ex:
    ```
      remove-padding "RW5jb2RlZE1lc3NhZ2U="
    ```
    Returns 
    ```
      "RW5jb2RlZE1lc3NhZ2U"
    ```
*/
remove-padding b64encoded/string -> string:
  return b64encoded.replace "=" "" --all=true

/**
  Adds padding to a base64 encoded string that has none
  Ex:
    ```
      add-padding "RW5jb2RlZE1lc3NhZ2U"
    ```
    Returns 
    ```
      "RW5jb2RlZE1lc3NhZ2U="
    ```
*/
add-padding b64encoded/string -> string:
  str-size := b64encoded.size
  pad-size := str-size % 4
  padding := "=" * pad-size
  return b64encoded + padding


/**
  Makes a nonce for use in authentication. Nonce returned is just a uuid without the dashes.
*/
make-nonce -> string:
  bytes := ByteArray 16
  i := 0
  bytes.size.repeat:
    bytes[i] = random
    i++
  uuid := uuid.Uuid bytes
  str := uuid.to-string.replace "-" "" --all=true
  return str

/**
    Performs an elementwise xor operation of two byte arrays and returns the resulting byte array. Checks array size ahead of time to
    ensure the arrays are the same size, and throws an error if they are not.
*/
xorbytearrs arr1/ByteArray arr2/ByteArray -> ByteArray:
  if arr1.size != arr2.size:
    throw "Arrays must be the same size"
  else:
    size := arr1.size
    out := ByteArray size
    i := 0
    size.repeat:
      out[i] = arr1[i] ^ arr2[i]
      i++
    return out

/**
  Implements the Hi function from RFC7804 specification: https://datatracker.ietf.org/doc/html/rfc7804#page-5
*/
hi password/string salt/string iterations/int -> ByteArray:
  bytepassword := password.to-byte-array
  decsalt := base64.decode (salt)
  appendedsalt := decsalt + #[0x00,0x00,0x00,0x01]
  u := hmac.hmac-sha256 --key=bytepassword appendedsalt
  ui := hmac.hmac-sha256 --key=bytepassword appendedsalt
  size := ui.size 
  (iterations - 1).repeat:
    ui = hmac.hmac-sha256 --key=bytepassword ui
    u = xorbytearrs u ui
  return u


/**
A SCRAM authorization client. Consruction of an instance of the SCRAMClient creates an http.Client that is used
for the requests. The client constructor must specify the following
--uri: The uri where the requests will be made. If this uri changes between requests, you will need to manually update it
using the setter for this field.
--username: the username that will be used for authentication.
--target-header: The name of the server response header that will contain the necessary SCRAM information.
--token-header: The name of the server response header that will contain the token after the final response from the server.

Common use:

  ```
      scram-client := SCRAMClient --uri="http://www.yourendpoint.com/yourpath" --un="user"--target-header="Www-Authenticate" --token-header="Authentication-Info"
      scram-client.authorize "pw"
      token := scram-client.token
  ```

*/
class SCRAMClient:
  client/http.Client := http.Client (net.open)
  uri/string
  salt/string? := null
  iterations/int? := null
  username/string
  target-header/string
  token-header/string
  //client-hello/string? := null
  is-authorized/bool := false
  server-hello/string? := null
  client-first/string? :=  null
  server-first/string? := null
  client-final/string? := null
  token/string? := null
  

  constructor --uri/string --un/string --target-header/string --token-header/string:
    this.uri = uri
    this.username = un
    this.target-header = target-header
    this.token-header = token-header
  
  make-req headers/http.Headers -> http.Response:
    resp := this.client.get 
      --uri=this.uri
      --headers=headers 
      --follow-redirects=false
    return resp

  get-header-data resp/http.Response header/string -> string?:
    headers := resp.headers
    data := headers.get header
    if data.size == 0:
      print "no header data\n"
      return null
    else:
      out := data.first
      return out

  get-server-hello -> none:
    encoded-un := base64.encode this.username
    depadded := remove-padding encoded-un
    header := http.Headers.from-map {"Authorization" : "HELLO username=$depadded"}
    resp := this.make-req header
    data := get-header-data resp this.target-header
    this.server-hello = data
    print "server-hello: $this.server-hello\n"
  
  get-first-resp ->none:
    nonce := make-nonce
    client-first-str :=  "n,,n=$username,r=$nonce"
    this.client-first = client-first-str
    print "client-first: $client-first-str\n"
    encoded := (base64.encode client-first-str).to-string.replace "=" "" --all=true
    msg := "$this.server-hello,data=$encoded"
    header := http.Headers.from-map {"Authorization" : msg}
    resp := make-req header
    data :=  get-header-data resp this.target-header
    b64 := ((data.split ",").first.split "=" --at-first=true)[1]
    padded := add-padding b64
    dec := (base64.decode padded).to-string
    this.server-first = dec
    print "server first: $this.server-first\n"
    parts := dec.split ","
    this.salt = (parts[1].split "=" --at-first=true)[1]
    this.iterations = int.parse (parts[2].split "=")[1]
    print ("salt : $this.salt\n iterations: $this.iterations\n")

  get-token resp/http.Response -> none:
      data := resp.headers.get this.token-header
      parts := data.first.split ","
      this.token = (parts[0].split "=" --at-first=true)[1]
      this.is-authorized = true
      print "client authorized with token $(this.token[0..4])...$(this.token[(this.token.size - 4)..(this.token.size)])"
      

  get-final-resp password/string -> none:
    saltedpw := hi password this.salt this.iterations
    client-key := hmac.hmac-sha256 --key=saltedpw "Client Key"
    stored-key := sha256 client-key
    client-first-parts := this.client-first.split ","
    client-first-bare := client-first-parts[2] + "," + client-first-parts[3]
    server-first-parts := this.server-first.split ","
    rval := server-first-parts[0]
    client-final-without-proof := "c=$(base64.encode "n,,"),$rval"
    auth-message := "$client-first-bare,$this.server-first,$client-final-without-proof"
    client-sig := hmac.hmac-sha256 --key=stored-key auth-message
    client-proof := xorbytearrs client-key client-sig
    msg := "c=$(base64.encode "n,,"),$rval,p=$(base64.encode client-proof)"
    this.client-final = msg
    print "client-final: $this.client-final" 
    enc := base64.encode this.client-final
    auth-string := "$this.server-hello,data=$(remove-padding enc)"
    headers := http.Headers.from-map {"Authorization" : auth-string}
    resp := make-req headers
    this.get-token resp


  /**
    Core function of the SCRAMClient class. This handles the following:
      1. Client Hello
      2. Parsing server hello
      3. Constructing and sending the client first
      4. Parsing the server first
      5. Contstructiong and sending the client final
      6. Parsing the server final and saving the token to the client token field
  */
  authorize password/string -> none:
    get-server-hello
    get-first-resp
    get-final-resp password
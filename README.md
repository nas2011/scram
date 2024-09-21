# SCRAM for Toit

This package implements a simple SCRAM authentication client which can be used to authenticate whenever SCRAM authentication is used.
The SCRAMClient class handles the authentication process and if successful, the SCRAMClient stores the token from the server.

Common use:

  ```
      scram-client := SCRAMClient --uri="http://www.yourendpoint.com/yourpath" 
            --un="username"
            --target-header="Www-Authenticate"                
            --token-header="Authentication-Info"
      scram-client.authorize "password"
      token := scram-client.token
  ```

A few key points: 

1. The contstructor takes a target-header argument which is the name of the header your server will be using to return its responses.

2. The token-header is the name of the header which will contain your token upon successful authentication.

Notes:

* This package has only been tested for SCRAM authentication against [SkySpark](https://skyfoundry.com/product). You could test against the open source version here: [Haxall](https://haxall.io/) if you do not have access to a SkySpark instance.

* If you test this and find it does not work in some application, let me know and I will be happy to try and troubleshoot.

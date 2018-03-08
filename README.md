# openam-auth-x509

*An OpenAM Authentication Module For Use With ICPBrasil Digital Certificate*

1. Build the module

```bash
   $ cd /path/to/openam-auth-x509
   $ mvn install
```

2. Install the module

Copy the x509 authentication module .jar file to WEB-INF/lib/ where OpenAM is deployed.

```bash
   $ cp target/openam-auth-x509*.jar /path/to/tomcat/webapps/openam/WEB-INF/lib/
```

Register the module with OpenAM using the ssoadm command.

```bash
   $ ssoadm \
   create-svc \
   --adminid amadmin \
   --password-file /tmp/pwd.txt \
   --xmlfile src/main/resources/amAuthX509.xml

   Service was added.
   $ ssoadm \
   register-auth-module \
   --adminid amadmin \
   --password-file /tmp/pwd.txt \
   --authmodule com.sun.identity.authentication.modules.x509.X509

   Authentication module was registered.
```

3. Restart OpenAM

```bash
   $ /path/to/tomcat/bin/shutdown.sh
   $ /path/to/tomcat/bin/startup.sh
   $ tail -1 /path/to/tomcat/logs/catalina.out
   INFO: Server startup in 14736 ms
```

4. Configure the module in OpenAM

Create a instance of the X509 module and name it X509, or choose another name, and use it by specifying it directly using query string (eg. http://openam.example.com:8080/openam/XUI/#login/&module=X509) or by adding it to an authentication chain.

The config parameters are mostly the same as the Cert module from OpenAM, the difference lies in the "SubjectAltNameExt Value Type to Access User Profile" where you can select the CPF or the CNPJ field that is in the ICPBrasil certificate.

For more instructions on using this authentication
module with OpenAM see the chapter,
*[Customizing Authentication Modules](https://backstage.forgerock.com/docs/openam/13/dev-guide/#sec-auth-spi)*,
in the OpenAM *Developer's Guide*.

This branch is for building a module with OpenAM 13.0.x.

* * *

The contents of this file are subject to the terms of the Common Development and
Distribution License (the License). You may not use this file except in compliance with the
License.

You can obtain a copy of the License at legal/CDDLv1.0.txt. See the License for the
specific language governing permission and limitations under the License.

When distributing Covered Software, include this CDDL Header Notice in each file and include
the License file at legal/CDDLv1.0.txt. If applicable, add the following below the CDDL
Header, with the fields enclosed by brackets [] replaced by your own identifying
information: "Portions copyright [year] [name of copyright owner]".

Copyright 2013-2015 ForgeRock AS.

Portions Copyrighted 2016 Lucas Rogerio Caetano Ferreira

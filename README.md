# Oauth2 Example
This project provides a sample of how to use the Oauth2 libraries and capabilities within Spring

The master branch uses the <code>@EnableOAuth2Sso</code> annotation to enable the filters and handshakes from the
various Oauth2 providers. Master also enables this for only one provider (Facebook)

For a more advanced look into the setup and configuration the oauth-client branch provides some
insight into all of the setup by manually configuring an oauth client in spring.
This branch also adds in support for another oauth authorization provider

## Running
To run this project you can just execute the main class <code>SsoExampleApplication</code>
and from there be able to visit the index.html page @ http://localhost:8080/

Clicking the Login button will prompt you for a Facebook username/password and then ask you for authorization (permission)
that you would grant the requesting application (SsoExampleApplication) to use for an identity and claims


## Oauth Client Config
You can see the more elaborate setup and configuation available if you utilize some of the [lower level
spring library on this branch](https://github.com/PhysicianExperience/sso-oauth2-example/tree/oauth-client)
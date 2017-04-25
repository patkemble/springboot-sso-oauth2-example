# Outh2 Client Configuration
This branch is a much more involved setup that shows the detail
behind some of the <code>@EnableOauth2Sso</code> annotation on the master branch.

This will also add in another Oauth2 provider (github) in addition to the existing Facebook provider setup

 Key points to reference in this branch
 * Propery declaration changes. Now the properties in the application.yml are rooted in their own entity trees
 * The use of a <code>CompositeFilter</code> for multiple Oauth2 providers

# Configure the Auth0 Provider with rate limiting
provider "auth0" {
  domain        = var.auth0_domain
  client_id     = var.auth0_client_id
  client_secret = var.auth0_client_secret
  
  # Set the maximum API capacity percentage to use
  # This prevents hitting Auth0 rate limits by proactively throttling requests
  # when the provider reaches 70% of the available rate limit capacity
  max_api_capacity = 70
  
  # Enable debug mode to see rate limiting logs
  debug = true
}

# Example resources that will benefit from rate limiting
resource "auth0_client" "my_client" {
  name            = "My Application"
  description     = "My Application Description"
  app_type        = "spa"
  callbacks       = ["https://example.com/callback"]
  allowed_origins = ["https://example.com"]
}

resource "auth0_user" "users" {
  count = 100 # Creating many users will benefit from rate limiting
  
  connection_name = "Username-Password-Authentication"
  email          = "user${count.index}@example.com"
  password       = "passpass$WORD1"
  
  depends_on = [auth0_client.my_client]
}

# Environment variable alternative:
# export AUTH0_MAX_API_CAPACITY=70
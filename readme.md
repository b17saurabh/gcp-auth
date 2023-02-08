It will be useful for the community members who are working on GCP or google APIs.
First you have to download json credentials for your gcp account, please refer to this documentation https://cloud.google.com/iam/docs/creating-managing-service-account-keys

Please refer to this git repo https://github.com/b17saurabh/gcp-auth/ , it's dotnet core class library which contains static method to GenerateJwt, ExchangeTokenAsync and GetAccessTokenAsync.
Let me explain each method for better clarity.

**GenerateJwt** - this method generates a signed JWT token from PrivateKey, PrivateKeyID, ServiceAccountEmail which are present in downloaded json from previous step and scope which will be different for different api endpoint like we have `https://www.googleapis.com/auth/compute` for google apis under compute.

**ExchangeTokenAsync** - this method need the generated JWT from previous step to generate the actual access token from google which will be valid to access google apis under that scope.

**GetAccessTokenAsync** - this is combination of above two methods, here you've pass parameters same as passed in GenerateJwt.

Please let me know if it requires any further explanation.

using Amazon.DynamoDBv2.DataModel;
using Amazon.DynamoDBv2;
using Amazon.Lambda.Core;
using AuthLambda.Entities;
using System.Security.Claims;
using System.Text;
using Amazon.Lambda.APIGatewayEvents;
using Newtonsoft.Json;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;

// Assembly attribute to enable the Lambda function's JSON input to be converted into a .NET class.
[assembly: LambdaSerializer(typeof(Amazon.Lambda.Serialization.SystemTextJson.DefaultLambdaJsonSerializer))]

namespace AuthLambda;

public class Function
{

    private const string key = "S0M3RAN0MS3CR3T!1!MAG1C!1!LONGER!1!KEY"; 
    public async Task<string> GenerateTokenAsync(APIGatewayHttpApiV2ProxyRequest request, ILambdaContext context)
    {
        var tokenRequest = JsonConvert.DeserializeObject<User>(request.Body);

        context.Logger.LogLine($"Received request body: {request.Body}");

        AmazonDynamoDBClient client = new AmazonDynamoDBClient();
        DynamoDBContext dbContext = new DynamoDBContext(client);
        //check if user exists in ddb
        var user = await dbContext.LoadAsync<User>(tokenRequest?.Email);
        if (user == null)
            throw new Exception("User Not Found!");
        if (user.Password != tokenRequest.Password)
            throw new Exception("Invalid Credentials!");
        var token = GenerateJWT(user);
        return token;
    }

    public string GenerateJWT(User user)
    {
        var claims = new List<Claim>
    {
        new(ClaimTypes.Email, user.Email),
        new(ClaimTypes.Name, user.Username)
    };

        // Converta a chave para bytes
        byte[] secret = Encoding.UTF8.GetBytes(key);

        // Garante que a chave tem tamanho suficiente
        if (secret.Length < 32)
            throw new ArgumentException("JWT secret key must be at least 32 bytes.");

        var signingCredentials = new SigningCredentials(new SymmetricSecurityKey(secret), SecurityAlgorithms.HmacSha256);

        var token = new JwtSecurityToken(
            claims: claims,
            expires: DateTime.UtcNow.AddMinutes(5),
            signingCredentials: signingCredentials
        );

        var tokenHandler = new JwtSecurityTokenHandler();
        return tokenHandler.WriteToken(token);
    }


    public APIGatewayCustomAuthorizerResponse ValidateTokenAsync(APIGatewayCustomAuthorizerRequest request, ILambdaContext context)
    {
        var authToken = request.Headers["authorization"];
        var claimsPrincipal = GetClaimsPrincipal(authToken);
        var effect = claimsPrincipal == null ? "Deny" : "Allow";

        context.Logger.LogLine($"effect result: {effect}");

        var principalId = claimsPrincipal == null ? "401" : claimsPrincipal?.FindFirst(ClaimTypes.Name)?.Value;
        return new APIGatewayCustomAuthorizerResponse()
        {
            PrincipalID = principalId,
            PolicyDocument = new APIGatewayCustomAuthorizerPolicy()
            {
                Statement = new List<APIGatewayCustomAuthorizerPolicy.IAMPolicyStatement>
            {
                new APIGatewayCustomAuthorizerPolicy.IAMPolicyStatement()
                {
                    Effect = effect,
                    Resource = new HashSet<string> { "arn:aws:execute-api:sa-east-1:503561418427:zly7plhnxg/*/*" },
                    Action = new HashSet<string> { "execute-api:Invoke" }
                }
            }
            }
        };
    }

    private ClaimsPrincipal GetClaimsPrincipal(string authToken)
    {
        var tokenHandler = new JwtSecurityTokenHandler();
        var validationParams = new TokenValidationParameters()
        {
            ValidateLifetime = true,
            ValidateAudience = false,
            ValidateIssuer = false,
            IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(key)),
        };
        try
        {
            return tokenHandler.ValidateToken(authToken, validationParams, out SecurityToken securityToken);
        }
        catch (Exception ex)
        {
            return null;
        }
    }
}

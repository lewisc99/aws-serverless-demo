using Amazon.Lambda.APIGatewayEvents;
using Amazon.Lambda.Core;

// Assembly attribute to enable the Lambda function's JSON input to be converted into a .NET class.
[assembly: LambdaSerializer(typeof(Amazon.Lambda.Serialization.SystemTextJson.DefaultLambdaJsonSerializer))]

namespace HelloLambda;

public class Function
{
    
    public APIGatewayHttpApiV2ProxyResponse FunctionHandler(APIGatewayHttpApiV2ProxyRequest request, ILambdaContext context)
    {
        request.QueryStringParameters.TryGetValue("name", out var name);
        name = name ?? "John Doe";
        var message = $"Hello {name}, from AWS lambda";
        return new APIGatewayHttpApiV2ProxyResponse
        {
            Body = message,
            StatusCode = 200,
        };
    }
}

import * as apigtw from "@aws-cdk/aws-apigatewayv2";
import * as httpIntegrations from "@aws-cdk/aws-apigatewayv2-integrations";
import * as lambda from "@aws-cdk/aws-lambda";
import * as cdk from "@aws-cdk/core";
import * as iam from "@aws-cdk/aws-iam";
import path from "path";
import config from "../../config.stack.json";

export class ApiStack extends cdk.Stack {
  constructor(scope: cdk.App, id: string) {
    super(scope, id);

    const handler = new lambda.Function(this, "handler", {
      code: new lambda.AssetCode(path.resolve(__dirname, "dist")),
      handler: `index.${config.api.handler}`,
      runtime: lambda.Runtime.NODEJS_14_X,
      description: "An lambda to accept our submissions",
      tracing: lambda.Tracing.ACTIVE,
    });

    const integration = new httpIntegrations.LambdaProxyIntegration({
      handler: handler,
    });

    const endpoint = new apigtw.HttpApi(this, `Endpoint${config.apiName}`, {
      apiName: `${config.apiName}`,
      createDefaultStage: true,
      description: "Integrating HTTP API to Lambda",
      corsPreflight: {
        allowCredentials: true,
        allowHeaders: ["Origin", "Content-Type", "Accept"],
        allowMethods: [
          apigtw.CorsHttpMethod.POST,
          apigtw.CorsHttpMethod.OPTIONS,
        ],
        allowOrigins: ["http://localhost:3000"],
      },
    });

    endpoint.addRoutes({
      path: "/submit",
      integration: integration,
      methods: [apigtw.HttpMethod.POST],
    });

    const stageDev = new apigtw.HttpStage(this, "Stage", {
      httpApi: endpoint,
      stageName: "dev",
      autoDeploy: true,
    });

    const statement = new iam.PolicyStatement({
      effect: iam.Effect.ALLOW,
      actions: ["secretsmanager:GetSecretValue"],
      resources: [
        "arn:aws:secretsmanager:us-east-1:695841149075:secret:/dev/recaptchav3/*",
      ],
    });

    handler.addToRolePolicy(statement);

    const outputUrlProd = new cdk.CfnOutput(this, "prod", {
      value: `${endpoint.url}`,
    });

    const outputUrlDev = new cdk.CfnOutput(this, "dev", {
      value: `${stageDev.url}`,
    });

    outputUrlProd._toCloudFormation;
    outputUrlDev._toCloudFormation;
  }
}

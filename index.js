// layers
const AWS = require('aws-sdk');
const parser = require('query-string-parser')

// AWS services
const cognitoProviderLib = require('aws-sdk/clients/cognitoidentityserviceprovider');
const cognitoidentityserviceprovider = new cognitoProviderLib();

// global vars
const globals = {};

function buildCustomError(httpStatus, cause) {
  switch (httpStatus) {
      case 400: {
          return JSON.stringify({
              httpStatus,
              type: 'BadRequest',
              cause
          });
      }
      case 401: {
        return JSON.stringify({
            httpStatus,
            type: 'Unauthorized',
            cause
        });
      }
      case 500: {
          return JSON.stringify({
              httpStatus,
              type: 'InternalServerError',
              cause
          });
      }
      default: {
          return JSON.stringify({
              httpStatus: 500,
              type: 'InternalServerError',
              cause
          });
      }
  }
}

async function refreshToken(clientId, poolId, token) {
    try {
        const data = await cognitoidentityserviceprovider.adminInitiateAuth({
            AuthFlow: 'REFRESH_TOKEN_AUTH',
            ClientId: clientId,
            UserPoolId: poolId,
            AuthParameters: {
                REFRESH_TOKEN: token
            }
        }).promise();

        if (!data) {
            throw buildCustomError(500, `Erro inesperado atualizando o token no Cognito`);
        }

        return {
            access_token: data.AuthenticationResult.IdToken,
            token_type: 'Bearer',
            expires_in: 3600,
            scope: globals.stage
        };
    } catch (err) {
        if (err.code === 'NotAuthorizedException') {
            throw buildCustomError(401, `${err.code}: ${err.message}`);
        }

        throw buildCustomError(500, err.message);
    }
}

exports.handler = async (event, context) => {
    try {
        // get stage from serverless deploy
        globals.stage = process.env.STAGE;

        // parse x-www-form-urlencoded
        const { clientId, poolId, refreshToken } = parser.fromQuery(event['body-json'])

        // refresh token
        return await refreshToken(clientId, poolId, refreshToken);
    } catch (err) {
        throw err;
    }
};

// layers
const AWS = require('aws-sdk');

// AWS services
const cognitoProviderLib = require('aws-sdk/clients/cognitoidentityserviceprovider');
const cognitoidentityserviceprovider = new cognitoProviderLib();

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
            accessToken: data.AuthenticationResult.IdToken,
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
        return await refreshToken(
            process.env.CLIENTID,
            process.env.POOLID,
            event.headers.Authorization
        );
    } catch (err) {
        throw err;
    }
};

// layers
const AWS = require('aws-sdk');

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

async function authorizeUser(clientId, poolId, username, password) {
    try {
      // perform authorization on Cognito user pool
        const data = await cognitoidentityserviceprovider.adminInitiateAuth({
            AuthFlow: 'ADMIN_NO_SRP_AUTH',
            ClientId: clientId,
            UserPoolId: poolId,
            AuthParameters: {
                USERNAME: username,
                PASSWORD: password            
            }
        }).promise();

        if (!data) {
            throw buildCustomError(500, `Erro inesperado autenticando o usuário ${username} no Cognito`);
        }

        // return access token
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
        console.log({
            env: process.env.STAGE,
            poolId: process.env.POOLID,
            clientId: process.env.CLIENTID
        });

        return {
            message: "success"
        }
    } catch (err) {
      throw err;
    }
};

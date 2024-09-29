
package com.br.lanchonete.auth;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.fasterxml.jackson.databind.ObjectMapper;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.cognitoidentityprovider.CognitoIdentityProviderClient;
import software.amazon.awssdk.services.cognitoidentityprovider.model.AdminInitiateAuthRequest;
import software.amazon.awssdk.services.cognitoidentityprovider.model.AdminInitiateAuthResponse;
import software.amazon.awssdk.services.cognitoidentityprovider.model.AuthFlowType;

import java.util.HashMap;
import java.util.Map;

public class CognitoAuthHandler implements RequestHandler<Map<String, String>, Map<String, Object>> {

    @Override
    public Map<String, Object> handleRequest(Map<String, String> input, Context context) {
        String clientId = input.get("client_id");
        String clientSecret = input.get("client_secret");

        CognitoIdentityProviderClient cognitoClient = CognitoIdentityProviderClient.builder()
                .region(Region.US_EAST_1)
                .build();

        try {
            AdminInitiateAuthRequest authRequest = AdminInitiateAuthRequest.builder()
                    .userPoolId("us-east-1_GI72zrpM8")
                    .clientId(clientId)
                    .authFlow(AuthFlowType.ADMIN_NO_SRP_AUTH)
                    .authParameters(new HashMap<String, String>() {{
                        put("SECRET_HASH", clientSecret);
                        put("USERNAME", clientId);
                        put("PASSWORD", clientSecret);
                    }})
                    .build();

            AdminInitiateAuthResponse authResponse = cognitoClient.adminInitiateAuth(authRequest);

            Map<String, Object> response = new HashMap<>();
            response.put("statusCode", 200);
            response.put("token", authResponse.authenticationResult().idToken());

            return response;

        } catch (Exception e) {
            Map<String, Object> errorResponse = new HashMap<>();
            errorResponse.put("statusCode", 401);
            errorResponse.put("error", "Unauthorized: Invalid client_id or client_secret");

            return errorResponse;
        }
    }
}

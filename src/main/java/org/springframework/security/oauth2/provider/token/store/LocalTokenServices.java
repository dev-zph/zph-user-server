package org.springframework.security.oauth2.provider.token.store;

import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.common.exceptions.InvalidTokenException;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.token.ResourceServerTokenServices;
import org.springframework.stereotype.Component;

/**
 * 本地token验证器, 不经过UAA直接验证, 能提高性能和效率
 * Created by zhangpenghui on 2017/08/06.
 */
@Component
public class LocalTokenServices implements ResourceServerTokenServices{

    private JwtAccessTokenConverter jwtTokenEnhancer;

    public void setJwtTokenEnhancer(JwtAccessTokenConverter jwtTokenEnhancer) {
        this.jwtTokenEnhancer = jwtTokenEnhancer;
    }

    @Override
    public OAuth2Authentication loadAuthentication(String accessTokenValue) throws AuthenticationException, InvalidTokenException {
        OAuth2AccessToken accessToken = this.readAccessToken(accessTokenValue);
        if (accessToken == null) {
            throw new InvalidTokenException("Invalid access token: " + accessTokenValue);
        }
        else if (accessToken.isExpired()) {
            throw new InvalidTokenException("Access token expired: " + accessTokenValue);
        }

        OAuth2Authentication result = jwtTokenEnhancer.extractAuthentication(jwtTokenEnhancer.decode(accessTokenValue));
        result.setDetails(accessTokenValue);
        if (result == null) {
            // in case of race condition
            throw new InvalidTokenException("Invalid access token: " + accessTokenValue);
        }
//        if (clientDetailsService != null) {
//            String clientId = result.getOAuth2Request().getClientId();
//            try {
//                clientDetailsService.loadClientByClientId(clientId);
//            }
//            catch (ClientRegistrationException e) {
//                throw new InvalidTokenException("Client not valid: " + clientId, e);
//            }
//        }
        return result;
    }

    @Override
    public OAuth2AccessToken readAccessToken(String accessTokenVal) {
        OAuth2AccessToken accessToken = this.convertAccessToken(accessTokenVal);
        if (jwtTokenEnhancer.isRefreshToken(accessToken)) {
            throw new InvalidTokenException("Encoded token is a refresh token");
        }
        return accessToken;
    }

    private OAuth2AccessToken convertAccessToken(String tokenValue) {
        return jwtTokenEnhancer.extractAccessToken(tokenValue, jwtTokenEnhancer.decode(tokenValue));
    }
}

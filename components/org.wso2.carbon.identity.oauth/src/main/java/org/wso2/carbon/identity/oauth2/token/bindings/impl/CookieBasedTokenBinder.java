/*
 * Copyright (c) 2019, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.oauth2.token.bindings.impl;

import org.apache.commons.lang.ArrayUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.oltu.oauth2.common.exception.OAuthSystemException;
import org.wso2.carbon.identity.oauth.cache.AuthorizationGrantCache;
import org.wso2.carbon.identity.oauth.cache.AuthorizationGrantCacheEntry;
import org.wso2.carbon.identity.oauth.cache.AuthorizationGrantCacheKey;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.dto.OAuth2AccessTokenReqDTO;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import static org.wso2.carbon.identity.oauth.common.OAuthConstants.GrantTypes.AUTHORIZATION_CODE;
import static org.wso2.carbon.identity.oauth.common.OAuthConstants.GrantTypes.IMPLICIT;

public class CookieBasedTokenBinder extends AbstractTokenBinder {

    private static final String BINDING_TYPE = "cookie";

    private static final String COOKIE_NAME = "tokenBindingValue";

    private List<String> supportedGrantTypes = Arrays.asList(AUTHORIZATION_CODE, IMPLICIT);

    @Override
    public String getBindingType() {

        return BINDING_TYPE;
    }

    @Override
    public List<String> getSupportedGrantTypes() {

        return Collections.unmodifiableList(supportedGrantTypes);
    }

    @Override
    public String getDisplayName() {

        return "Cookie";
    }

    @Override
    public String getDescription() {

        return "Bind token to the browser cookie.";
    }

    @Override
    public String getOrGenerateTokenBindingValue(HttpServletRequest request) throws OAuthSystemException {

        Cookie[] cookies = request.getCookies();
        if (ArrayUtils.isNotEmpty(cookies)) {
            Optional<Cookie> tokenBindingCookieOptional = Arrays.stream(cookies)
                    .filter(t -> COOKIE_NAME.equals(t.getName())).findAny();
            if (tokenBindingCookieOptional.isPresent()) {
                //TODO
                return tokenBindingCookieOptional.get().getValue();
            }
        }

        return UUID.randomUUID().toString();
    }

    @Override
    public Optional<String> getTokenBindingValue(OAuth2AccessTokenReqDTO oAuth2AccessTokenReqDTO) {

        if (AUTHORIZATION_CODE.equals(oAuth2AccessTokenReqDTO.getGrantType()) && StringUtils
                .isNotBlank(oAuth2AccessTokenReqDTO.getAuthorizationCode())) {

            AuthorizationGrantCacheKey cacheKey = new AuthorizationGrantCacheKey(
                    oAuth2AccessTokenReqDTO.getAuthorizationCode());
            AuthorizationGrantCacheEntry authorizationGrantCacheEntry = AuthorizationGrantCache.getInstance()
                    .getValueFromCacheByCode(cacheKey);
            if (authorizationGrantCacheEntry != null && StringUtils
                    .isNotBlank(authorizationGrantCacheEntry.getTokenBindingValue())) {
                return Optional.of(authorizationGrantCacheEntry.getTokenBindingValue());
            }
        }
        return Optional.empty();
    }

    @Override
    public void setTokenBindingValueForResponse(HttpServletResponse response, String tokenBindingValue) {

        Cookie cookie = new Cookie(COOKIE_NAME, tokenBindingValue);
        cookie.setSecure(true);
        cookie.setHttpOnly(true);
        cookie.setPath("/");
        response.addCookie(cookie);
    }

    @Override
    public void clearTokenBindingElements(HttpServletRequest request, HttpServletResponse response) {

        Cookie[] cookies = request.getCookies();
        if (ArrayUtils.isNotEmpty(cookies)) {
            Arrays.stream(cookies).filter(t -> COOKIE_NAME.equals(t.getName())).findAny().ifPresent(cookie -> {
                cookie.setMaxAge(0);
                cookie.setSecure(true);
                cookie.setPath("/");
                response.addCookie(cookie);
            });
        }
    }

    @Override
    public boolean validate() throws IdentityOAuth2Exception {

        return true;
    }
}

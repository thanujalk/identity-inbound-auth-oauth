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

import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.token.bindings.TokenBinder;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import static org.wso2.carbon.identity.oauth.common.OAuthConstants.GrantTypes.AUTHORIZATION_CODE;
import static org.wso2.carbon.identity.oauth.common.OAuthConstants.GrantTypes.IMPLICIT;

public class CookieBasedTokenBinder extends AbstractTokenBinder {

    private static final String BINDING_TYPE = "cookie";

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
    public boolean validate() throws IdentityOAuth2Exception {

        return true;
    }
}

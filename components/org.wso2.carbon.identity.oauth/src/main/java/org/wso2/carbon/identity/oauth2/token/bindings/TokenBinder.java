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

package org.wso2.carbon.identity.oauth2.token.bindings;

import org.wso2.carbon.identity.oauth.common.token.bindings.TokenBinderInfo;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;

import java.util.Optional;

public interface TokenBinder extends TokenBinderInfo {

    Optional<TokenBinding> getTokenBinding(String tokenId) throws IdentityOAuth2Exception;

    void storeTokenBinding(TokenBinding tokenBinding, String tenantDomain) throws IdentityOAuth2Exception;

    void deleteTokenBinding(String tokenId) throws IdentityOAuth2Exception;

    boolean validate() throws IdentityOAuth2Exception;
}

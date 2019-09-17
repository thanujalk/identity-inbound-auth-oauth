package org.wso2.carbon.identity.oauth2.token.bindings.impl;

import org.apache.commons.lang.StringUtils;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.dao.OAuthTokenPersistenceFactory;
import org.wso2.carbon.identity.oauth2.token.bindings.TokenBinder;
import org.wso2.carbon.identity.oauth2.token.bindings.TokenBinding;
import org.wso2.carbon.utils.multitenancy.MultitenantConstants;

import java.util.Optional;

public abstract class AbstractTokenBinder implements TokenBinder {

    @Override
    public Optional<TokenBinding> getTokenBinding(String tokenId) throws IdentityOAuth2Exception {

        if (StringUtils.isBlank(tokenId)) {
            throw new IdentityOAuth2Exception("Invalid token id.");
        }

        return OAuthTokenPersistenceFactory.getInstance().getTokenBindingMgtDAO().getTokenBinding(tokenId);
    }

    @Override
    public void storeTokenBinding(TokenBinding tokenBinding, String tenantDomain) throws IdentityOAuth2Exception {

        if (StringUtils.isBlank(tokenBinding.getTokenId())) {
            throw new IdentityOAuth2Exception("Invalid token id.");
        }

        if (StringUtils.isBlank(tokenBinding.getBindingType())) {
            throw new IdentityOAuth2Exception("Invalid binding type.");
        }

        if (StringUtils.isBlank(tokenBinding.getBindingReference())) {
            throw new IdentityOAuth2Exception("Invalid binding reference.");
        }

        if (StringUtils.isBlank(tokenBinding.getBindingValue())) {
            throw new IdentityOAuth2Exception("Invalid binding value.");
        }

        int tenantId = MultitenantConstants.SUPER_TENANT_ID;
        if (StringUtils.isNotBlank(tenantDomain) && !MultitenantConstants.SUPER_TENANT_DOMAIN_NAME
                .equals(tenantDomain)) {
            tenantId = IdentityTenantUtil.getTenantId(tenantDomain);
        }

        OAuthTokenPersistenceFactory.getInstance().getTokenBindingMgtDAO().storeTokenBinding(tokenBinding, tenantId);
    }

    @Override
    public void deleteTokenBinding(String tokenId) throws IdentityOAuth2Exception {

        if (StringUtils.isBlank(tokenId)) {
            throw new IdentityOAuth2Exception("Invalid token id.");
        }

        OAuthTokenPersistenceFactory.getInstance().getTokenBindingMgtDAO().deleteTokenBinding(tokenId);
    }
}

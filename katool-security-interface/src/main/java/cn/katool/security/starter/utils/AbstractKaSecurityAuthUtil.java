package cn.katool.security.starter.utils;

import cn.katool.security.core.config.KaSecurityCoreConfig;
import cn.katool.util.auth.AuthUtil;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.OutputStream;

public interface AbstractKaSecurityAuthUtil<T> extends  DefaultKaSecurityAuthUtilInterface<T> {
    @Override
    default T getPayLoadWithHeader() {
        return DefaultKaSecurityAuthUtilInterface.super.getPayLoadWithHeader();
    }

    @Override
    default T getPayLoadWithDubboRPC() {
        return DefaultKaSecurityAuthUtilInterface.super.getPayLoadWithDubboRPC();
    }

    @Override
    default T getPayLoad() {
        return DefaultKaSecurityAuthUtilInterface.super.getPayLoad();
    }

    @Override
    default String getTokenWithDubboRPC() {
        return DefaultKaSecurityAuthUtilInterface.super.getTokenWithDubboRPC();
    }

    default HttpServletRequest getRequest(){
        HttpServletRequest request=((ServletRequestAttributes) RequestContextHolder.currentRequestAttributes()).getRequest();;
        return request;
    }

    default HttpServletResponse getResponse(){
        HttpServletResponse response=((ServletRequestAttributes) RequestContextHolder.currentRequestAttributes()).getResponse();
        return response;
    }

    default String login(T payload){
        // 生成Token
        String token = AuthUtil.createToken(payload);
        HttpServletResponse response = getResponse();
        response.setHeader(KaSecurityCoreConfig.CURRENT_TOKEN_HEADER, token);
        return token;
    }

}

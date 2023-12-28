package cn.katool.security.auth.config;

import cn.katool.security.auth.model.entity.KaSecurityUser;
import cn.katool.security.core.logic.KaSecurityAuthLogic;
import cn.katool.security.core.logic.KaToolSecurityAuthQueue;
import cn.katool.security.core.model.entity.KaSecurityValidMessage;
import cn.katool.security.starter.utils.KaSecurityAuthUtil;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.BooleanUtils;
import org.apache.commons.lang3.ObjectUtils;
import org.springframework.context.annotation.Bean;
import org.springframework.stereotype.Component;

import java.util.List;
@Component
@Slf4j
public class AuthConfig extends KaSecurityAuthUtil<KaSecurityUser> implements KaSecurityAuthLogic {
    @Override
    public KaSecurityValidMessage doCheckLogin(Boolean onlyCheckLogin) {
        KaSecurityUser payLoad = this.getPayLoad();
        if (ObjectUtils.isEmpty(payLoad)){
            return KaSecurityValidMessage.unLogin();
        }
        if (BooleanUtils.isFalse(onlyCheckLogin)){
            log.info("当前接口不仅仅检查登录情况");
            return KaSecurityValidMessage.success();
        }
        return KaSecurityValidMessage.onlyLogin();
    }

    @Override
    public KaSecurityValidMessage doAuth(List<String> roleList) {
        KaSecurityUser payLoad = this.getPayLoad();
        String userRole = payLoad.getUserRole();
        if (roleList.contains(userRole)){
            return KaSecurityValidMessage.success();
        }
        return KaSecurityValidMessage.noAuth();
    }
    @Bean
    public void initer(){
        log.info("AuthConfig init");
        KaToolSecurityAuthQueue.add(this);
    }
}

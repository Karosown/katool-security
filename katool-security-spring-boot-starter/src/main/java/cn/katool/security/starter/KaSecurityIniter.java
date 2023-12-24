package cn.katool.security.starter;

import org.apache.dubbo.config.spring.context.annotation.DubboComponentScan;
import org.apache.dubbo.config.spring.context.annotation.EnableDubbo;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.EnableAspectJAutoProxy;
import org.springframework.stereotype.Component;

@Component
@EnableAspectJAutoProxy(proxyTargetClass = true, exposeProxy = true)
public class KaSecurityIniter {

    private final String version = "V1.0.0.SNAPSHOT";

    @Bean
    public void init(){
        System.out.println(
                " ██   ██           ██████████                    ██        ████████                                ██   ██           \n" +
                "░██  ██           ░░░░░██░░░                    ░██       ██░░░░░░                                ░░   ░██    ██   ██\n" +
                "░██ ██    ██████      ░██      ██████   ██████  ░██      ░██         █████   █████  ██   ██ ██████ ██ ██████ ░░██ ██ \n" +
                "░████    ░░░░░░██     ░██     ██░░░░██ ██░░░░██ ░██ █████░█████████ ██░░░██ ██░░░██░██  ░██░░██░░█░██░░░██░   ░░███  \n" +
                "░██░██    ███████     ░██    ░██   ░██░██   ░██ ░██░░░░░ ░░░░░░░░██░███████░██  ░░ ░██  ░██ ░██ ░ ░██  ░██     ░██   \n" +
                "░██░░██  ██░░░░██     ░██    ░██   ░██░██   ░██ ░██             ░██░██░░░░ ░██   ██░██  ░██ ░██   ░██  ░██     ██    \n" +
                "░██ ░░██░░████████    ░██    ░░██████ ░░██████  ███       ████████ ░░██████░░█████ ░░██████░███   ░██  ░░██   ██     \n" +
                "░░   ░░  ░░░░░░░░     ░░      ░░░░░░   ░░░░░░  ░░░       ░░░░░░░░   ░░░░░░  ░░░░░   ░░░░░░ ░░░    ░░    ░░   ░░      \n" +
                "                                                                                                          "+version);
    }
}

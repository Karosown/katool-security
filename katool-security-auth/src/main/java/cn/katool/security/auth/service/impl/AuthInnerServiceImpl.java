package cn.katool.security.auth.service.impl;

import cn.katool.security.auth.exception.BusinessException;
import cn.katool.security.auth.exception.ErrorCode;
import cn.katool.security.auth.mapper.AuthMapper;
import cn.katool.security.auth.service.AuthInnerService;
import cn.katool.security.core.annotation.AuthServiceCheck;
import cn.katool.security.core.model.dto.auth.AuthAddRequest;
import cn.katool.security.core.model.dto.auth.AuthUpdateRequest;
import cn.katool.security.auth.model.entity.Auth;
import com.baomidou.mybatisplus.core.conditions.query.QueryWrapper;
import com.baomidou.mybatisplus.extension.service.impl.ServiceImpl;
import org.apache.commons.lang3.ObjectUtils;
import org.apache.commons.lang3.StringUtils;
import org.springframework.beans.BeanUtils;
import org.springframework.stereotype.Service;

import javax.annotation.Resource;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;

/**
* @author 30398
* @description 针对表【auth】的数据库操作Service实现
* @createDate 2023-05-27 11:29:05
*/
@Service
@AuthServiceCheck(
        excludeMethods = {"reload","getlistByIsOpen"})
public class AuthInnerServiceImpl extends ServiceImpl<AuthMapper, Auth>
    implements AuthInnerService {
    @Override
    public Boolean insert(AuthAddRequest addRequest) {
        if (ObjectUtils.isEmpty(addRequest)){
            throw new BusinessException(ErrorCode.PARAMS_ERROR);
        }
        addRequest.setMethod(addRequest.getMethod().toUpperCase(Locale.ROOT));
        addRequest.setUri(addRequest.getUri().toLowerCase(Locale.ROOT));
        addRequest.setRoute(addRequest.getRoute().toLowerCase(Locale.ROOT));
        String fid = addRequest.getFid();
        String method = addRequest.getMethod();
        String uri = addRequest.getUri();
        String route = addRequest.getRoute();
        List<String> authRole = addRequest.getAuthRole();
        String operUser = addRequest.getOperUser();
        Boolean checkLogin = addRequest.getCheckLogin();
        Boolean isDef = addRequest.getIsDef();
        if (StringUtils.isAnyBlank(method,uri,route,operUser)) {
            throw new BusinessException(ErrorCode.PARAMS_ERROR);
        }
        if (ObjectUtils.isEmpty(authRole)||authRole.size()<1){
            authRole.add("admin");
        }
        Auth auth=new Auth();
        BeanUtils.copyProperties(addRequest,auth);
        auth.setAuthRoles(authRole);
        boolean save = this.save(auth);
        return save;
    }



    @Override
    public Boolean change(AuthUpdateRequest authUpdateRequest) {
        if (ObjectUtils.isEmpty(authUpdateRequest)){
            throw new BusinessException(ErrorCode.PARAMS_ERROR);
        }
        String id = authUpdateRequest.getId();
        String method = authUpdateRequest.getMethod();
        String fid = authUpdateRequest.getFid();
        String uri = authUpdateRequest.getUri();
        String route = authUpdateRequest.getRoute();
        List<String> authRole = authUpdateRequest.getAuthRole();
        String operUser = authUpdateRequest.getOperUser();
        Boolean checkLogin = authUpdateRequest.getCheckLogin();
        Boolean isDef = authUpdateRequest.getIsDef();
        if (StringUtils.isAnyBlank(method,uri,route,operUser)) {
            throw new BusinessException(ErrorCode.PARAMS_ERROR);
        }
        if (ObjectUtils.isEmpty(authRole)||authRole.size()<1){
            authRole.add("admin");
        }
        Auth auth=new Auth();
        BeanUtils.copyProperties(authUpdateRequest,auth);
        auth.setAuthRoles(authRole);

        QueryWrapper<Auth> updateWrapper = new QueryWrapper<>();
        updateWrapper.eq(StringUtils.isNotBlank(id),"id",id)
                .or()
                .eq("method",method)
                .eq("route",route)
                .eq("uri",uri);
        boolean save = this.update(auth, updateWrapper);
        return save;
    }
    @Override
    public Boolean open(String method, String uri, String route) {
        if (StringUtils.isAnyBlank(method,uri,route)){
            throw new BusinessException(ErrorCode.PARAMS_ERROR);
        }
        Auth auth = new Auth();
        auth.setIsOpen(true);

        QueryWrapper<Auth> query = new QueryWrapper<>();
        query.eq("method",method)
                .eq("route",route)
                .eq("uri",uri);
        boolean update = this.update(auth, query);
        return update;
    }

    @Override
    public Boolean open(String id) {
        if (StringUtils.isAnyBlank(id)) {
            throw new BusinessException(ErrorCode.PARAMS_ERROR);
        }
        Auth auth=new Auth().setId(id)
                .setOpen(true);
        boolean update = this.updateById(auth);
        return update;
    }
    @Override
    public Boolean open(List<String> ids) {
        if (ObjectUtils.isEmpty(ids)) {
            throw new BusinessException(ErrorCode.PARAMS_ERROR);
        }
        List<Auth> auths=new ArrayList<>();
        ids.forEach(v->{
            auths.add(new Auth().setId(v).setOpen(true));
        });
        boolean update = this.updateBatchById(auths);
        return update;
    }

    @Override
    public Boolean close(List<String> ids) {
        if (ObjectUtils.isEmpty(ids)) {
            throw new BusinessException(ErrorCode.PARAMS_ERROR);
        }
        List<Auth> auths=new ArrayList<>();
        ids.forEach(v->{
            auths.add(new Auth().setId(v).setOpen(false));
        });
        boolean update = this.updateBatchById(auths);
        return update;
    }

    @Override
    public Boolean close(String id) {
        if (StringUtils.isAnyBlank(id)) {
            throw new BusinessException(ErrorCode.PARAMS_ERROR);
        }
        Auth auth=new Auth().setId(id)
                .setOpen(false);
        boolean update = this.updateById(auth);
        return update;
    }

    @Override
    public Boolean close(String method, String uri, String route) {
        if (StringUtils.isAnyBlank(method,uri,route)){
            throw new BusinessException(ErrorCode.PARAMS_ERROR);
        }
        Auth auth = new Auth();
        auth.setIsOpen(false);

        QueryWrapper<Auth> query = new QueryWrapper<>();
        query.eq("method",method)
                .eq("route",route)
                .eq("uri",uri);
        boolean update = this.update(auth, query);
        return update;
    }

    @Override
    public List<Auth> getlistByIsOpen() {

        QueryWrapper<Auth> isOpen = new QueryWrapper<>();
        isOpen.eq("is_open", true);
        return this.list(isOpen);
    }

    @Override
    public Auth getOne(String method, String requestURI, String contextPath) {

        QueryWrapper<Auth> query = new QueryWrapper<>();
        query.eq("method",method)
                .eq("uri",requestURI)
                .eq("route",contextPath);
        return this.getOne(query);
    }

    @Override
    public Boolean isOpen(String method, String uri, String route){
        if (StringUtils.isAnyBlank(method,uri,route)){
            throw new BusinessException(ErrorCode.PARAMS_ERROR);
        }

        QueryWrapper<Auth> query = new QueryWrapper<>();
        query.eq("method",method)
                .eq("route",route)
                .eq("uri",uri);
        Auth one = this.getOne(query);
        if (ObjectUtils.isEmpty(one)) {
            return null;
        }
        return one.getIsOpen();
    }

    @Override
    public Boolean reload() {
        List<Auth> list = this.list();
        AtomicInteger index= new AtomicInteger();
        AtomicBoolean res= new AtomicBoolean(true);
        CompletableFuture<Void> voidCompletableFuture =     CompletableFuture.runAsync(() -> {
            int end = index.get() + list.size() / 3 + 1;
            List<Auth> auths = list.subList(index.get(), end);
            auths.stream().forEach(v -> {
                v.setIsOpen(false);
            });
            res.set(res.get() & this.saveOrUpdateBatch(auths, auths.size() / 3 + 1));
            index.set(end);
        });
        voidCompletableFuture.join();
       return res.get();
    }
}

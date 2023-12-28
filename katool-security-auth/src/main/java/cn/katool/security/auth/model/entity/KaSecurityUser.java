package cn.katool.security.auth.model.entity;

import com.baomidou.mybatisplus.annotation.TableField;
import com.baomidou.mybatisplus.annotation.TableLogic;
import com.baomidou.mybatisplus.annotation.TableName;
import java.io.Serializable;
import java.util.Date;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.EqualsAndHashCode;
import lombok.NoArgsConstructor;

/**
 * 
 * @TableName ka_security_user
 */
@TableName(value ="ka_security_user")
@Data
@AllArgsConstructor
@NoArgsConstructor
@EqualsAndHashCode
public class KaSecurityUser implements Serializable {
    /**
     * 
     */
    @TableField(value = "id")
    private Integer id;

    /**
     * 
     */
    @TableField(value = "user_name")
    private String userName;

    /**
     * 
     */
    @TableField(value = "pass_word")
    private String passWord;

    /**
     * 
     */
    @TableField(value = "user_role")
    private String userRole;

    /**
     * 
     */
    @TableLogic(delval = "1", value = "0")
    @TableField(value = "is_delete")
    private Integer isDelete;

    /**
     * 
     */
    @TableField(value = "created_time")
    private Date createdTime;

    /**
     * 
     */
    @TableField(value = "update_time")
    private Date updateTime;

    @TableField(exist = false)
    private static final long serialVersionUID = 1L;


}
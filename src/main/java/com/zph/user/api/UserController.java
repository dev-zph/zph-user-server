package com.zph.user.api;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.ResponseBody;
/**
 * @notes
 * @autho zph
 * @createTime 2018/9/30 11:57
 */
@RequestMapping(value = "/v1/user")
@Controller
@ResponseBody
public class UserController {

    @RequestMapping(value = "/test", method = RequestMethod.POST)
    public String purchaseInsertStock(){
        return "system";
    }
}

package com.zph.user.api;

import com.zph.user.remote.order.RemoteOrderCtl;
import org.springframework.beans.factory.annotation.Autowired;
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

    @Autowired
    private RemoteOrderCtl remoteOrderCtl;

    @RequestMapping(value = "/test", method = RequestMethod.POST)
    public String purchaseInsertStock(){
        String result = remoteOrderCtl.orderList();
        System.out.println(result);
        return "system";
    }
}

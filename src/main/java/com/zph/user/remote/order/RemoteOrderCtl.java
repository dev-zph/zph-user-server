package com.zph.user.remote.order;

import com.zph.user.remote.order.FallBack.RemoteOrderCtlFallBack;
import org.springframework.cloud.netflix.feign.FeignClient;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;

/**
 * @notes
 * @autho zph
 * @createTime 2018/10/2 11:17
 */
@FeignClient(value = "order",fallback = RemoteOrderCtlFallBack.class)
public interface RemoteOrderCtl {

    @RequestMapping(value = "/v1/order/orderList", method = RequestMethod.POST)
    String orderList();
}

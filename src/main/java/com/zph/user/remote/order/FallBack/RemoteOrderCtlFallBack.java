package com.zph.user.remote.order.FallBack;

import com.zph.user.remote.order.RemoteOrderCtl;
import org.springframework.stereotype.Component;

/**
 * @notes
 * @autho zph
 * @createTime 2018/10/2 11:18
 */
@Component
public class RemoteOrderCtlFallBack implements RemoteOrderCtl {
    @Override
    public String orderList() {
        return "链接超时";
    }
}

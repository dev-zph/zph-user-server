package com.zph.user;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.cloud.client.discovery.EnableDiscoveryClient;
import org.springframework.cloud.netflix.feign.EnableFeignClients;

@SpringBootApplication(scanBasePackages = "com.zph")
@EnableDiscoveryClient
@EnableFeignClients
public class ZphUserServerApplication {

	public static void main(String[] args) {
		SpringApplication.run(ZphUserServerApplication.class, args);
	}
}

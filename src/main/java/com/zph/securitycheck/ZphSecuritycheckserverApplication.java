package com.zph.securitycheck;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.cloud.client.discovery.EnableDiscoveryClient;

@SpringBootApplication
public class ZphSecuritycheckserverApplication {

	public static void main(String[] args) {
		SpringApplication.run(ZphSecuritycheckserverApplication.class, args);
	}
}

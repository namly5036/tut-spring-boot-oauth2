/*
 * Copyright 2012-2015 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.example;

import java.util.Collections;
import java.util.Map;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.http.HttpStatus;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.authentication.HttpStatusEntryPoint;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@SpringBootApplication
@RestController
public class SocialApplication extends WebSecurityConfigurerAdapter {

	@RequestMapping("/user")
	public Map<String, Object> user(@AuthenticationPrincipal OAuth2User principal) {
		return Collections.singletonMap("name", principal.getAttribute("login"));
		// principal:
		//Name: [31858132],
		// Granted Authorities: [[ROLE_USER, SCOPE_read:user]],
		// User Attributes: [{login=namly5036,
		// id=31858132,
		// node_id=MDQ6VXNlcjMxODU4MTMy,
		// avatar_url=https://avatars.githubusercontent.com/u/31858132?v=4,
		// gravatar_id=, url=https://api.github.com/users/namly5036,
		// html_url=https://github.com/namly5036,
		// followers_url=https://api.github.com/users/namly5036/followers,
		// following_url=https://api.github.com/users/namly5036/following{/other_user},
		// gists_url=https://api.github.com/users/namly5036/gists{/gist_id},
		// starred_url=https://api.github.com/users/namly5036/starred{/owner}{/repo},
		// subscriptions_url=https://api.github.com/users/namly5036/subscriptions,
		// organizations_url=https://api.github.com/users/namly5036/orgs,
		// repos_url=https://api.github.com/users/namly5036/repos,
		// events_url=https://api.github.com/users/namly5036/events{/privacy},
		// received_events_url=https://api.github.com/users/namly5036/received_events,
		// type=User,
		// site_admin=false,
		// name=null, company=null, blog=, location=null, email=null, hireable=null, bio=null, twitter_username=null,
		// public_repos=3, public_gists=0, followers=0, following=0,
		// created_at=2017-09-11T15:42:49Z,
		// updated_at=2023-01-29T08:38:36Z, private_gists=0, total_private_repos=0, owned_private_repos=0, disk_usage=447, collaborators=0, two_factor_authentication=false, plan={name=free, space=976562499, collaborators=0, private_repos=10000}}]
	}

	@Override
	protected void configure(HttpSecurity http) throws Exception {
		// @formatter:off
		http
			.authorizeRequests(a -> a
				.antMatchers("/", "/error", "/webjars/**").permitAll()
				.anyRequest().authenticated()
			)
			.exceptionHandling(e -> e
				.authenticationEntryPoint(new HttpStatusEntryPoint(HttpStatus.UNAUTHORIZED))
			)
			.csrf(c -> c
				.csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())
			)
			.logout(l -> l
				.logoutSuccessUrl("/").permitAll()
			)
			.oauth2Login();
		// @formatter:on
	}

	public static void main(String[] args) {
		SpringApplication.run(SocialApplication.class, args);
		//auto redirect to index, not need to return MVC view
	}

}
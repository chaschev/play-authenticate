package com.feth.play.module.pa.controllers;

import com.feth.play.module.pa.PlayAuthenticate;
import play.mvc.Controller;
import play.mvc.Http.Request;
import play.mvc.Http.Response;
import play.mvc.Result;

public class Authenticate extends Controller {
	private static final String PAYLOAD_KEY = "p";
	
	public static void noCache(final Response response) {
		// http://stackoverflow.com/questions/49547/making-sure-a-web-page-is-not-cached-across-all-browsers
		response.setHeader(Response.CACHE_CONTROL, "no-cache, no-store, must-revalidate");  // HTTP 1.1
		response.setHeader(Response.PRAGMA, "no-cache");  // HTTP 1.0.
		response.setHeader(Response.EXPIRES, "0");  // Proxies.
	}

	public static Result authenticateJava(final String provider) {
        return (Result) authenticate(provider);
	}

    public static play.api.mvc.Result authenticateScala(final String provider) {
        return (play.api.mvc.Result) authenticate(provider);
    }

    private static Object authenticate(String provider) {
        noCache(response());

        final String payload = getQueryString(request(), PAYLOAD_KEY);
        return PlayAuthenticate.handleAuthentication(provider, ctx(), payload);
    }
	
	public static Result logoutJava() {
        return (Result) logout();
	}

    public static play.api.mvc.Result logoutScala() {
        return (play.api.mvc.Result) logout();
    }

    private static Object logout() {
        noCache(response());

        return PlayAuthenticate.logout(session());
    }

    // TODO remove on Play 2.1
	public static String getQueryString(final Request r, final Object key) {
		final String[] m = r.queryString().get(key);
		if(m != null && m.length > 0) {
			return m[0];
		}
		return null;
	}
}

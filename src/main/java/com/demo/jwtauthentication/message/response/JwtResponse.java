package com.demo.jwtauthentication.message.response;

import com.google.gson.JsonObject;

public class JwtResponse {
    private String token;
    private String type = "Bearer";
    private JsonObject data;
   
    public String getAccessToken() {
        return token;
    }

    public void setAccessToken(String accessToken) {
        this.token = accessToken;
    }

    public String getTokenType() {
        return type;
    }

    public void setTokenType(String tokenType) {
        this.type = tokenType;
    }

	public JsonObject getData() {
		return data;
	}

	public void setData(JsonObject data) {
		this.data = data;
	}
}
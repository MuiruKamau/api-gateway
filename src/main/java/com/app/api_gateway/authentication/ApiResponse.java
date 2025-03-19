package com.app.api_gateway.authentication;

public class ApiResponse {
    private String token;
    private String message;
    private int statusCode;

    // Constructor with all fields
    public ApiResponse(String token, String message, int statusCode) {
        this.token = token;
        this.message = message;
        this.statusCode = statusCode;
    }

    // Convenience constructor without token
    public ApiResponse(String message, int statusCode) {
        this(null, message, statusCode); // Call the main constructor with null token
    }

    // Getters and Setters
    public String getToken() {
        return token;
    }

    public void setToken(String token) {
        this.token = token;
    }

    public String getMessage() {
        return message;
    }

    public void setMessage(String message) {
        this.message = message;
    }

    public int getStatusCode() {
        return statusCode;
    }

    public void setStatusCode(int statusCode) {
        this.statusCode = statusCode;
    }
}



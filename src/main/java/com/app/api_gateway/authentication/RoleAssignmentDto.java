package com.app.api_gateway.authentication;

import com.app.api_gateway.authentication.Role;
import lombok.Data;

import java.util.Set;

@Data
public class RoleAssignmentDto {
    private String username;
    private Set<Role> roles;
}


package com.Csecurity.passkey.controller;     

import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;


@Controller
public class AppController {

    @GetMapping("/")
    public String welcome(Model model, Authentication authentication) {
        model.addAttribute( "username", authentication.getName());
        return "Index.html"; 
    }


}
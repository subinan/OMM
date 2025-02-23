package com.omm.member.controller;

import com.omm.exception.CustomException;
import com.omm.jwt.JwtFilter;
import com.omm.member.model.dto.AuthDto;
import com.omm.member.model.dto.RegistDto;
import com.omm.member.model.dto.TokenDto;
import com.omm.member.service.AuthService;
import com.omm.member.service.DidService;
import com.omm.member.service.GetCredentialService;
import com.omm.member.service.MemberService;
import com.omm.util.UrlInfo;
import com.omm.util.error.ErrorCode;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.ModelAndView;
import org.springframework.web.servlet.view.RedirectView;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;

@RestController
@RequiredArgsConstructor
@RequestMapping("/sign")
public class RedirectController {

    private final AuthService authService;

    private final DidService didService;

    private final MemberService memberService;

    private final UrlInfo urlInfo;

    private final GetCredentialService getCredentialService;



    @GetMapping("/{type}")
    public String moveToCC24Sign(@PathVariable String type) throws IOException {
        String toUrl = urlInfo.getCc24Front() + "/login?type=";

        if (type.equals("SIGNIN") || type.equals("SIGNUP")) {
            toUrl += type;
        } else {
            throw new CustomException(ErrorCode.CANNOT_AUTHORIZE_MEMBER);
        }
        return toUrl;
    }


    @GetMapping("/certificate")
    public String moveToCC24Certificate() {
        return urlInfo.getCc24Front() + "/certificate";
//        switch (type) {
//            case "UniversityCredential":
//            case "CertificateCredential":
//            case "JobCredential":
//            case "IncomeCredential":
//            case "EstateCredential":
//            case "HealthCredential":
//                return "http://localhost:3000/certificate?type=" + type;
//            default:
//                throw new CustomException(ErrorCode.CANNOT_AUTHORIZE_MEMBER);
//        }
    }


    @PostMapping("/{type}")
    public String doSign(@PathVariable("type") String type, @RequestBody AuthDto authDto) throws URISyntaxException {
        System.out.println(authDto.getHolderDid());
        System.out.println(authDto.getVpJwt());

        System.out.println(memberService.existDidAddress(authDto.getHolderDid()));
        URI target = null;

        String did = authDto.getHolderDid();

        // 로그인, 회원가입에 따라 분기
        switch (type) {
            case "SIGNUP":
                if (!memberService.existDidAddress(authDto.getHolderDid())) {
                    RegistDto registDto = didService.registAuth(authDto);
                    memberService.addMember(registDto);
                    memberService.addMemberCert(registDto.getHolderDid());
                    memberService.addNewInfo(authDto.getHolderDid());
                    memberService.addNewFiltering(authDto.getHolderDid());
                    String jwt = authService.authenticate(authDto.getHolderDid(), authDto.getVpJwt());
                    return urlInfo.getOmmFront() + "/signup?jwt="+jwt;
                } else {
//                    return new ResponseEntity<>("로그인하세요.", HttpStatus.BAD_REQUEST);
                    return urlInfo.getCc24Front() + "/login?type=SIGNIN";
                }
            case "SIGNIN":
                if (memberService.existDidAddress(authDto.getHolderDid())) {
                    String jwt = authService.authenticate(authDto.getHolderDid(), authDto.getVpJwt());
                    return urlInfo.getOmmFront() + "/main?jwt="+jwt;
                } else {
//                    return new ResponseEntity<>("회원가입하세요.", HttpStatus.BAD_REQUEST);
                    return urlInfo.getCc24Front() + "/login?type=SIGNUP";
                }
            default:
                throw new CustomException(ErrorCode.CANNOT_AUTHORIZE_MEMBER);
        }
//        HttpHeaders httpHeaders = new HttpHeaders();
//        httpHeaders.add(JwtFilter.AUTHORIZATION_HEADER, "Bearer " + jwt);
    }

    @PostMapping("/certificate/{type}")
    public String getCertificate(@PathVariable("type") String type, @RequestBody AuthDto authDto) {
        getCredentialService.getCertificate(type, authDto);
        return urlInfo.getOmmFront() + "/myprofile";
    }

}

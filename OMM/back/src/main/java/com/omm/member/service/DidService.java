package com.omm.member.service;

import com.google.gson.Gson;
import com.omm.exception.CustomException;
import com.omm.member.model.dto.AuthDto;
import com.omm.member.model.dto.RegistDto;
import com.omm.member.model.dto.SubjectsDto;
import com.omm.util.UrlInfo;
import com.omm.util.error.ErrorCode;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.*;
import org.springframework.stereotype.Service;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestTemplate;

import java.util.Calendar;
import java.util.HashMap;
import java.util.Map;

@Service
@RequiredArgsConstructor
public class DidService {


    private static final Logger logger = LoggerFactory.getLogger(AuthService.class);

    private final RestTemplate restTemplate;

    private final UrlInfo urlInfo;


    /**
     * 로그인 인증 (DID 주소와 VP 일치 확인)
     *
     * @param authDto
     * @return
     */
    public boolean loginAuth(AuthDto authDto) {
        SubjectsDto subjects = verifyVP(authDto);
        if (subjects.getSubjects().get("did") == null ||
                !authDto.getHolderDid().equals(subjects.getSubjects().get("did").get("address"))) {
            return false;
        }
        return true;
    }

    public RegistDto registAuth(AuthDto authDto) {
        SubjectsDto subjects = verifyVP(authDto);
        Map<String, Object> personalId = subjects.getSubjects().get("personalId");
        if (personalId == null ||
                personalId.get("birthdate") == null ||
                personalId.get("gender") == null ||
                personalId.get("imageUrl") == null) {
            throw new CustomException(ErrorCode.INVALID_VP);
        }

        return RegistDto.builder()
                .holderDid(authDto.getHolderDid())
                .age((short) (Calendar.getInstance().get(Calendar.YEAR) -
                        Integer.parseInt(((String) personalId.get("birthdate")).substring(0, 4)) + 1))
                .gender((String) personalId.get("gender"))
                .imageUrl((String) personalId.get("imageUrl"))
                .build();

    }

    /**
     * DID VERIFIER 서버랑 통신해서 VP의 유효성 검증
     *
     * @param authDto
     * @return
     */
    private SubjectsDto verifyVP(AuthDto authDto) {
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);

        Gson gsonObj = new Gson();

        Map<String, String> requestBody = new HashMap<>();
        requestBody.put("holderDid", authDto.getHolderDid());
        requestBody.put("vpJwt", authDto.getVpJwt());

        HttpEntity<String> requestEntity = new HttpEntity<>(gsonObj.toJson(requestBody), headers);

        String url = urlInfo.getNodeapi() +  "/api/node/presentation";
        HttpMethod httpMethod = HttpMethod.POST;

        try {
            ResponseEntity<String> responseEntity = restTemplate.exchange(url, httpMethod,
                    requestEntity, String.class);
            return gsonObj.fromJson(responseEntity.getBody(), SubjectsDto.class);
        } catch (HttpClientErrorException e) {
            logger.debug(e.getMessage());
            logger.debug(e.getResponseBodyAsString());
            throw new CustomException(ErrorCode.INVALID_VP);
        }

    }
}

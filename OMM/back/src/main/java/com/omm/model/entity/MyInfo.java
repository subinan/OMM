package com.omm.model.entity;

import com.omm.model.entity.enums.*;
import lombok.Data;

import javax.persistence.*;

@Entity
@Data
@Table(name = "myinfo")
public class MyInfo {

    @Id @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "info_id")
    private Long id;

    @OneToOne
    @JoinColumn(name = "member_id", nullable = false)
    private Member member;

    @Column(name = "highschoool", nullable = false)
    private String highschool;

    @Column(name = "lat")
    private float lat;

    @Column(name = "lng")
    private float lng;

    @Column(name = "height", nullable = false)
    private short height;

    @Column(name = "contact_sytle", nullable = false)
    @Enumerated(EnumType.STRING)
    private InfoContactStyle contactStyle;

    @Column(name = "drinking_style", nullable = false)
    @Enumerated(EnumType.STRING)
    private InfoDrinkingStyle drinkingStyle;

    @Column(name = "smoking_style", nullable = false)
    @Enumerated(EnumType.STRING)
    private InfoSmokingStyle smokingStyle;

    @Column(name = "military", nullable = false)
    @Enumerated(EnumType.STRING)
    private InfoMilitary military;

    @Column(name = "pet", nullable = false)
    @Enumerated(EnumType.STRING)
    private InfoPet pet;

    @Column(name = "mbti")
    @Enumerated(EnumType.STRING)
    private InfoMBTI mbti;

    @Column(name = "pr")
    private String pr;

    @Column(name = "age", nullable = false)
    private short age;
}

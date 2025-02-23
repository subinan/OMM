package com.omm.model.entity;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.hibernate.annotations.ColumnDefault;
import org.hibernate.annotations.DynamicInsert;

import javax.persistence.*;

@Entity
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
@DynamicInsert
@Table(name = "membercert")
public class MemberCert {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "cert_id")
    private Long id;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "member_id", nullable = false)
    private Member member;

    @Column(name = "university")
    @ColumnDefault("false")
    private boolean university;

    @Column(name = "university_name")
    private String universityName;

    @Column(name = "job")
    @ColumnDefault("false")
    private boolean job;

    @Column(name = "job_names")
    private String jobNames;

    @Column(name = "certificate")
    @ColumnDefault("false")
    private boolean certificate;

    @Column(name = "certificate_names")
    private String certificateNames;

    @Column(name = "health")
    @ColumnDefault("false")
    private boolean health;

    @Column(name = "health_info")
    private String healthInfo;

    @Column(name = "estate")
    @ColumnDefault("false")
    private boolean estate;

    @Column(name = "estate_amount")
    private String estateAmount;

    @Column(name = "income")
    @ColumnDefault("false")
    private boolean income;

    @Column(name = "income_amount")
    private String incomeAmount;
}

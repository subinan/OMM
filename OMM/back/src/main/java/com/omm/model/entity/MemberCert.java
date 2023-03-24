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

    @ManyToOne
    @JoinColumn(name = "member_id", nullable = false)
    private Member member;

    @Column(name = "university")
    @ColumnDefault("false")
    private boolean university = false;

    @Column(name = "job")
    @ColumnDefault("false")
    private boolean job = false;

    @Column(name = "certificate")
    @ColumnDefault("false")
    private boolean certificate = false;

    @Column(name = "health")
    @ColumnDefault("false")
    private boolean health = false;

    @Column(name = "estate")
    @ColumnDefault("false")
    private boolean estate = false;

    @Column(name = "income")
    @ColumnDefault("false")
    private boolean income = false;
}

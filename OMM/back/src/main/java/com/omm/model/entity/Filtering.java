package com.omm.model.entity;

import com.omm.model.entity.enums.FilterContactStyle;
import com.omm.model.entity.enums.FilterDrinkingStyle;
import com.omm.model.entity.enums.FilterSmokingStyle;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import javax.persistence.*;

@Entity
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
@Table(name = "filtering")
public class Filtering {

    @Id @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "filtering_id")
    private Long id;

    @OneToOne
    @JoinColumn(name = "member_id", nullable = false)
    private Member member;

    @Column(name = "age_min", nullable = false)
    private int ageMin;

    @Column(name = "age_max", nullable = false)
    private int ageMax;

    @Column(name = "height_min", nullable = false)
    private int heightMin;

    @Column(name = "height_max", nullable = false)
    private int heightMax;

    @Column(name = "range_min")
    private int rangeMin = 0;

    @Column(name = "range_max", nullable = false)
    private int rangeMax;

    @Column(name = "contact_style", nullable = false)
    @Enumerated(EnumType.STRING)
    private FilterContactStyle contactStyle;

    @Column(name = "drinking_style", nullable = false)
    @Enumerated(EnumType.STRING)
    private FilterDrinkingStyle drinkingStyle;

    @Column(name = "smoking_style", nullable = false)
    @Enumerated(EnumType.STRING)
    private FilterSmokingStyle smokingStyle;

}

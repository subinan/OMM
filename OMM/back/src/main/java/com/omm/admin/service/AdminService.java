package com.omm.admin.service;

import com.omm.admin.model.dto.ReportDto;
import com.omm.admin.model.request.CreateReportRequestDto;
import com.omm.admin.model.request.PunishMemberRequestDto;
import com.omm.admin.model.response.GetReportResponseDto;
import com.omm.repository.ReportRepository;
import com.omm.exception.admin.ReportExceptionCode;
import com.omm.exception.admin.ReportRuntimeException;
import com.omm.exception.member.MemberExceptionCode;
import com.omm.exception.member.MemberRuntimeException;
import com.omm.repository.MemberRepository;
import com.omm.model.entity.Member;
import com.omm.model.entity.Report;
import com.omm.model.entity.enums.ReportCategory;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;

import java.time.LocalDate;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

@Service
@RequiredArgsConstructor
public class AdminService {

    private final ReportRepository reportRepository;

    private final MemberRepository memberRepository;


    /**
     * 채팅방에서 새로운 신고 내역을 전송한다.
     *
     * @param createReportRequestDto 신고 내역 정보
     * @param currentMemberDidAddress         신고자 멤버
     * @return
     */
    public boolean createReport(CreateReportRequestDto createReportRequestDto, String currentMemberDidAddress,
                                MultipartFile image) {

        // 현재 등록중인 멤버를 찾는다.
        Member member = memberRepository.findByDidAddress(currentMemberDidAddress)
                .orElseThrow(() -> new MemberRuntimeException(MemberExceptionCode.MEMBER_NOT_EXISTS));

        // 신고당한 멤버를 찾는다.
        Member target = memberRepository.findById(createReportRequestDto.getTargetId())
                .orElseThrow(() -> new MemberRuntimeException(MemberExceptionCode.MEMBER_NOT_EXISTS));

        // report 를 생성한다.
        try {
            Report report = Report.builder()
                    .member(member)
                    .reported(target)
                    .reason(createReportRequestDto.getReason())
                    .image(image.getBytes())
                    .state(createReportRequestDto.isState())
                    .category(ReportCategory.valueOf(createReportRequestDto.getCategory())).build();
            reportRepository.save(report);
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * 신고내역을 불러온다
     *
     * @return
     */
    public List<GetReportResponseDto> getReportList() {
        // 모든 리포트를 가져온다
        List<Report> reports = reportRepository.findAll();
        // 반환할 형식 리스트를 생성한다
        List<GetReportResponseDto> result = new ArrayList<>();
        // 반환할 리스트로 하나씩 넣는다
        reports.forEach(report -> {
            result.add(GetReportResponseDto.builder()
                            .reportId(report.getId())
                            .memberNickname(report.getMember().getNickname())
                            .reportedMemberNickname(report.getReported().getNickname())
                            .state(report.isState())
                            .category(report.getCategory().name())
                    .build());
        });
        return result;
    }

    /**
     * 특정 신고 내역을 조회한다
     *
     * @param reportId 신고내역 아이디
     * @return
     */
    public ReportDto getReport(Long reportId) {
        // 해당 리포트를 찾는다
        Report report = reportRepository.findById(reportId)
                .orElseThrow(() -> new ReportRuntimeException(ReportExceptionCode.REPORT_NOT_FOUND));
        Map<String, Object> memberInfo = new HashMap<>();
        Member member = report.getMember();
        memberInfo.put("memberId", member.getId());
        memberInfo.put("memberNickname", member.getNickname());

        Map<String, Object> reportedMemberInfo = new HashMap<>();
        Member reportedMember = report.getReported();
        reportedMemberInfo.put("reportedMemberId", reportedMember.getId());
        reportedMemberInfo.put("reportedMemberNickname", reportedMember.getNickname());
        // 반환 형식에 맞게 변경하여 전송한다.
        ReportDto result = ReportDto.builder()
                .reportId(report.getId())
                .memberInfo(memberInfo)
                .reportedMemberInfo(reportedMemberInfo)
                .reason(report.getReason())
                .image(report.getImage())
                .state(report.isState())
                .category(report.getCategory().name()).build();
        return result;
    }

    /**
     * 신고내역을 "처리완료" 상태로 변경한다.
     *
     * @param reportId 신고내역 아이디
     */
    public void processReport(Long reportId) {
        // 처리할 신고내역을 찾는다.
        Report report = reportRepository.findById(reportId)
                .orElseThrow(() -> new ReportRuntimeException(ReportExceptionCode.REPORT_NOT_FOUND));
        // 세팅하고 저장한다.
        report.setState(true);
        reportRepository.save(report);
    }

    /**
     * 특정 사용자를 처벌한다.
     *
     * @param punishMemberRequestDto 처벌할 정보
     */
    public void punishMember(PunishMemberRequestDto punishMemberRequestDto) {
        // 정보가 제대로 왔는지 확인하고
        if (punishMemberRequestDto != null) {
            switch (punishMemberRequestDto.getType()) {
                // 처리할 게 없다면 넘어감
                case "nothing":
                    break;
                // 계정 정지 처리
                case "suspend":
                    Member suspendTarget = memberRepository.findById(punishMemberRequestDto.getMemberId())
                            .orElseThrow(() -> new MemberRuntimeException(MemberExceptionCode.MEMBER_NOT_EXISTS));
                    LocalDate tempDate = suspendTarget.getSuspendDate();
                    if(tempDate == null){
                        tempDate = LocalDate.now();
                    }
                    suspendTarget.setSuspendDate(tempDate.plusDays(punishMemberRequestDto.getPeriod()));
                    memberRepository.save(suspendTarget);
                    break;
                // 계정 삭제 처리
                case "resign":
                    Member resignTarget = memberRepository.findById(punishMemberRequestDto.getMemberId())
                            .orElseThrow(() -> new MemberRuntimeException(MemberExceptionCode.MEMBER_NOT_EXISTS));
                    resignTarget.setBlack(true);
                    memberRepository.save(resignTarget);
                    break;
                // 그 외엔 잘못된 요청이다
                default:
                    throw new ReportRuntimeException(ReportExceptionCode.REPORT_BAD_REQUEST);
            }
        } else throw new ReportRuntimeException(ReportExceptionCode.REPORT_BAD_REQUEST);
    }
}

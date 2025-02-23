import React, { useState, useEffect, lazy, Suspense } from 'react';

import './Pslider.css';
import { Tooltip } from 'react-tooltip';
import 'react-tooltip/dist/react-tooltip.css';
import Modal from 'react-modal';
import './MyProfile.css';
import ImageUploader from './ImageUploader';
import pencil from '../../assets/pencil.svg';
import imagesetting from '../../assets/imagesetting.svg';
import estateYes from '../../assets/estate_yes.svg';
import estateNo from '../../assets/estate_no.svg';
import jobYes from '../../assets/job_yes.svg';
import jobNo from '../../assets/job_no.svg';
import incomeYes from '../../assets/income_yes.svg';
import incomeNo from '../../assets/income_no.svg';
import healthYes from '../../assets/health_yes.svg';
import healthNo from '../../assets/health_no.svg';
import universityYes from '../../assets/university_yes.svg';
import universityNo from '../../assets/university_no.svg';
import certificateYes from '../../assets/certificate_yes.svg';
import certificateNo from '../../assets/certificate_no.svg';
import Navbar from '../../components/nav-bar';
import userarrow from '../../assets/userarrow.svg';
import MyinfoSetModal from './MyinfoSetModal';
import MyinfoSetModal2 from './MyinfoSetModal2';
import MyinfoSetModal3 from './MyinfoSetModal3';
import http from '../../api/http';

const Pslider = lazy(() => import('../../components/Pslider'));

function InterestList({ interest }) {
  return (
    <div>
      <div>
        <div />
      </div>

      {interest.map((item) => (
        <button
          key={item.interest_list_id}
          className="bg-white border border-black rounded-full text-sm px-4"
        >
          {item.name}
        </button>
      ))}
    </div>
  );
}

function MyProfile({ profileNav }) {
  const certinfo = {
    university: false,
    job: false,
    certificate: false,
    health: false,
    estate: false,
    income: false,
  };

  const whereLoca = async () => {
    await fetch(
      'https://dapi.kakao.com/v2/local/geo/coord2address.json?x=126.8115825&y=35.205739&input_coord=WGS84',
    )
      .then((res) => {
        console.log(res);
      })
      .catch((err) => {
        console.log(err);
      });
  };
  const [MymodalIsOpen, setMyIsOpen] = useState(false);
  const [MymodalIsOpen2, setMyIsOpen2] = useState(false);
  const [MymodalIsOpen3, setMyIsOpen3] = useState(false);
  const [uploadImg, setuploadImg] = useState(false);
  const [disabled, setDisabled] = useState(true);
  const [newPr, setnewPr] = useState('');

  const token = localStorage.getItem('accesstoken');

  const handleClick = () => {
    setDisabled(false);
  };
  const openMyModal = () => {
    setMyIsOpen(true);
  };
  const closeMyModal = () => {
    setMyIsOpen(false);
  };
  const openMyModal2 = () => {
    setMyIsOpen2(true);
  };
  const closeMyModal2 = () => {
    setMyIsOpen2(false);
  };
  const openMyModal3 = () => {
    setMyIsOpen3(true);
  };
  const closeMyModal3 = () => {
    setMyIsOpen3(false);
  };
  const openImageModal = () => {
    setuploadImg(true);
  };
  const closeImageModal = () => {
    setuploadImg(false);
  };
  const [newCertinfo, setCert] = useState(certinfo);
  const [interest, setInterest] = useState([]);
  const [basicInfomation, setInfo] = useState([]);
  const [filterInfomation, setFilter] = useState([]);

  async function Freshinfo() {
    await http({
      method: 'get',
      url: '/member',
      headers: {
        Authorization: `Bearer ${token}`,
      },
    })
      .then((res) => {
        setInfo(res.data);
      })
      .catch((err) => {
        console.log(err);
      });
  }

  async function FreshCert() {
    await http({
      method: 'get',
      url: '/member/certificate',
      headers: {
        Authorization: `Bearer ${token}`,
      },
    })
      .then((res) => {
        setCert(res.data);
      })
      .catch((err) => {
        console.log(err);
      });
  }
  async function sendPr() {
    await http({
      method: 'put',
      url: '/member/pr',
      headers: {
        Authorization: `Bearer ${token}`,
      },
      data: { pr: newPr },
    })
      .then((res) => {
        console.log(res);
      })
      .catch((err) => {
        console.log(err);
      });
  }

  async function FreshFilter() {
    await http({
      method: 'get',
      url: '/member/filtering',
      headers: {
        Authorization: `Bearer ${token}`,
      },
    })
      .then((res) => {
        setFilter(res.data);
      })
      .catch((err) => {
        console.log(err);
      });
  }

  async function FreshInterest() {
    await http({
      method: 'get',
      url: '/member/interest-list',
      headers: {
        Authorization: `Bearer ${token}`,
      },
    })
      .then((res) => {
        setInterest(res.data.interestList);
      })
      .catch((err) => {
        console.log(err);
      });
  }

  useEffect(() => {
    FreshCert();
    FreshInterest();
    FreshFilter();
    Freshinfo();
    whereLoca();
  }, []);

  async function toCert() {
    await http({
      method: 'get',
      url: '/sign/certificate',
      headers: {
        Authorization: `Bearer ${token}`,
      },
    })
      .then((res) => {
        console.log(res);
        window.location.href = res.data;
      })
      .catch((err) => {
        console.log(err);
      });
  }
  let drinkingStyleText;
  if (basicInfomation.drinking_style === 'NOT') {
    drinkingStyleText = '안함';
  } else if (basicInfomation.drinking_style === 'SOMETIMES') {
    drinkingStyleText = '가끔';
  } else if (basicInfomation.drinking_style === 'OFTEN') {
    drinkingStyleText = '자주';
  } else if (basicInfomation.drinking_style === 'EVERYDAY') {
    drinkingStyleText = '매일';
  } else if (basicInfomation.drinking_style === 'ONLY_FRIENDS') {
    drinkingStyleText = '친구들 만날 떄만';
  } else if (basicInfomation.drinking_style === 'STOPPING') {
    drinkingStyleText = '금주중';
  }
  let drinkingStyleText2;
  if (filterInfomation.drinking_style === 'NONE') {
    drinkingStyleText2 = '상관없음';
  } else if (filterInfomation.drinking_style === 'PREFER_NO') {
    drinkingStyleText2 = '안마셨으면 좋겠음';
  } else if (filterInfomation.drinking_style === 'PREFER_YES') {
    drinkingStyleText2 = '잘마셨으면 좋겠음';
  }
  let smokingStyleText;
  if (basicInfomation.smoking_style === 'NOT') {
    smokingStyleText = '안함';
  } else if (basicInfomation.smoking_style === 'SOMETIMES') {
    smokingStyleText = '가끔';
  } else if (basicInfomation.smoking_style === 'OFTEN') {
    smokingStyleText = '자주';
  } else if (basicInfomation.smoking_style === 'STOPPING') {
    smokingStyleText = '금연중';
  }
  let smokingStyleText2;
  if (filterInfomation.smoking_style === 'NONE') {
    smokingStyleText2 = '상관없음';
  } else if (filterInfomation.smoking_style === 'PREFER_NO') {
    smokingStyleText2 = '비흡연자 선호';
  } else if (filterInfomation.smoking_style === 'PREFER_YES') {
    smokingStyleText2 = '흡연자 선호';
  }
  let contactStyleText;
  if (basicInfomation.contact_style === 'PREFER_MSG') {
    contactStyleText = '카톡자주하는편';
  } else if (basicInfomation.contact_style === 'PREFER_CALL') {
    contactStyleText = '전화선호';
  } else if (basicInfomation.contact_style === 'PREFER_FACECALL') {
    contactStyleText = '영상통화선호';
  } else if (basicInfomation.contact_style === 'NOT_MSG') {
    contactStyleText = '카톡 별로 안하는 편';
  } else if (basicInfomation.contact_style === 'PREFER_OFFLINE') {
    contactStyleText = '직접 만나는 걸 선호';
  }
  let contactStyleText2;
  if (filterInfomation.contact_style === 'PREFER_MSG') {
    contactStyleText2 = '카톡자주하는편';
  } else if (filterInfomation.contact_style === 'PREFER_CALL') {
    contactStyleText2 = '전화선호';
  } else if (filterInfomation.contact_style === 'NONE') {
    contactStyleText2 = '상관없음';
  } else if (filterInfomation.contact_style === 'PREFER_FACECALL') {
    contactStyleText2 = '영상통화선호';
  } else if (filterInfomation.contact_style === 'NOT_MSG') {
    contactStyleText2 = '카톡 별로 안하는 편';
  } else if (filterInfomation.contact_style === 'PREFER_OFFLINE') {
    contactStyleText2 = '직접 만나는 걸 선호';
  }

  let petText;
  if (basicInfomation.pet === 'NOT') {
    petText = '안키움';
  } else if (basicInfomation.pet === 'DOG') {
    petText = '강아지';
  } else if (basicInfomation.pet === 'CAT') {
    petText = '고양이';
  } else if (basicInfomation.pet === 'HAMSTER') {
    petText = '햄스터';
  } else if (basicInfomation.pet === 'LIZARD') {
    petText = '도마뱀';
  } else if (basicInfomation.pet === 'ETC') {
    petText = '기타';
  }

  let militaryText;
  if (basicInfomation.military === 'NONE') {
    militaryText = '해당없음';
  } else if (basicInfomation.military === 'EXEMPT') {
    militaryText = '면제';
  } else if (basicInfomation.military === 'COMPLETE') {
    militaryText = '군필';
  } else if (basicInfomation.military === 'YET') {
    militaryText = '미필';
  }

  return (
    <div className="relative h-[48.75rem] overflow-x-hidden">
      <div className="text-center">
        <Modal
          className="MyinfoModal"
          isOpen={MymodalIsOpen}
          onRequestClose={closeMyModal}
          style={{
            content: {
              top: '50%',
              left: '50%',
              right: 'auto',
              bottom: 'auto',
              marginRight: '-50%',
              transform: 'translate(-50%, -50%)',
            },
          }}
        >
          <MyinfoSetModal
            setModal={closeMyModal}
            basicInformation={basicInfomation}
          />
        </Modal>
      </div>
      <div className="text-center">
        <Modal
          className="MyinfoModal"
          isOpen={MymodalIsOpen2}
          onRequestClose={closeMyModal2}
          style={{
            content: {
              top: '50%',
              left: '50%',
              right: 'auto',
              bottom: 'auto',
              marginRight: '-50%',
              transform: 'translate(-50%, -50%)',
            },
          }}
        >
          <MyinfoSetModal2
            setModal={closeMyModal2}
            filterInfomation={filterInfomation}
          />
        </Modal>
      </div>
      <div className="text-center">
        <Modal
          className="MyinfoModal3"
          isOpen={MymodalIsOpen3}
          onRequestClose={closeMyModal3}
          style={{
            content: {
              top: '50%',
              left: '50%',
              right: 'auto',
              bottom: 'auto',
              marginRight: '-50%',
              transform: 'translate(-50%, -50%)',
            },
          }}
        >
          <MyinfoSetModal3 setModal={closeMyModal3} />
        </Modal>
      </div>
      <div>
        <div className="absolute w-full z-5">
          <Suspense fallback={<div>Loading...</div>}>
            <Pslider profileImg={basicInfomation.profileimgs} />
          </Suspense>
          <div>
            <Modal
              isOpen={uploadImg}
              // onAfterOpen={afterOpenModal}
              onRequestClose={closeImageModal}
              className="ProfileImgModal"
              overlayClassName="ProfileImgOverlay"
              ariaHideApp={false}
            >
              <ImageUploader setModal={closeImageModal} />
            </Modal>
          </div>
          <div className="mx-auto sm:w-[37rem] w-[22.5rem] rounded-3xl bg-white text-left z-10 shadow-lg border-t">
            <div className="infodetail">
              <div className="text-right">
                <div
                  className="inline-block object-right mt-5"
                  onClick={() => {
                    openImageModal();
                  }}
                  aria-hidden
                >
                  <img src={imagesetting} alt="$" />
                </div>
              </div>

              <div className="mb-8">
                <span className="text-4xl m-3 font-light mb-8 text-[#364C63]">
                  {basicInfomation.nickname}
                </span>
                <span className="text-[#364C63] text-2xl">
                  {' '}
                  {basicInfomation.age}
                </span>
              </div>
              <div>
                <hr className="thickhr" />
                <div className="my-1">
                  <div className="text-2xl m-3 text-[#364C63]">자기소개</div>
                  <div />
                  <div>
                    <textarea
                      maxLength={40}
                      disabled={disabled}
                      className="m-3 break-words h-20 resize-none overflow-hidden focus:ring-2 focus:ring-blue-200 text-slate-600 text-sm bg-transparent border-none outline-none w-full font-sans"
                      type="text"
                      value={newPr}
                      placeholder={
                        basicInfomation.pr
                          ? basicInfomation.pr
                          : '당신에게 OMM...'
                      }
                      onChange={(e) => {
                        setnewPr(e.target.value);
                      }}
                    />
                  </div>
                  <span className="flex justify-end">
                    {disabled && (
                      <button>
                        {' '}
                        <img
                          onClick={handleClick}
                          src={pencil}
                          alt=""
                          aria-hidden
                        />
                      </button>
                    )}
                    {!disabled && (
                      <button>
                        {' '}
                        <span onClick={sendPr} aria-hidden>
                          변경완료
                        </span>
                      </button>
                    )}
                  </span>
                </div>
                <hr className="thickhr" />
                <div className="font-light">
                  <div className="text-2xl m-3 font-light mb-8 text-[#364C63]">
                    내 정보
                  </div>
                  <div className="flex justify-between m-3">
                    <div className="">
                      <span className="font-sans font-semibold text-black">
                        키
                      </span>
                    </div>
                    <div>
                      <div className="flex items-center ">
                        <span
                          onClick={() => {
                            openMyModal();
                          }}
                          aria-hidden
                          className="hover:text-[#F59FB1] hover:cursor-pointer font-sans font-semibold text-black"
                        >
                          {basicInfomation.height}
                          {' '}
                          cm
                        </span>
                        <div
                          onClick={() => {
                            openMyModal();
                          }}
                          aria-hidden
                        >
                          <img src={userarrow} alt="" className="w-3 ml-2" />
                        </div>
                      </div>
                    </div>
                  </div>
                  <hr />

                  <div className="flex justify-between m-3">
                    <div className="">
                      <span className="font-sans font-semibold text-black">
                        음주 스타일
                      </span>
                    </div>
                    <div>
                      <div className="flex items-center">
                        <span
                          onClick={() => {
                            openMyModal();
                          }}
                          aria-hidden
                          className="hover:text-[#F59FB1] hover:cursor-pointer font-sans font-semibold text-black"
                        >
                          {drinkingStyleText}
                        </span>
                        <div
                          onClick={() => {
                            openMyModal();
                          }}
                          aria-hidden
                        >
                          <img src={userarrow} alt="" className="w-3 ml-2" />
                        </div>
                      </div>
                    </div>
                  </div>
                  <hr />
                  <hr />
                  <div className="flex justify-between m-3">
                    <div className="">
                      <span className="font-sans font-semibold text-black">
                        연락 스타일
                      </span>
                    </div>
                    <div>
                      <div className="flex items-center">
                        <span
                          onClick={() => {
                            openMyModal();
                          }}
                          aria-hidden
                          className="hover:text-[#F59FB1] hover:cursor-pointer font-sans font-semibold text-black"
                        >
                          {contactStyleText}
                        </span>
                        <div
                          onClick={() => {
                            openMyModal();
                          }}
                          aria-hidden
                        >
                          <img src={userarrow} alt="" className="w-3 ml-2" />
                        </div>
                      </div>
                    </div>
                  </div>
                  <hr />
                  <div className="flex justify-between m-3">
                    <div className="">
                      <span className="font-sans font-semibold text-black">
                        흡연 스타일
                      </span>
                    </div>
                    <div>
                      <div className="flex items-center">
                        <span
                          onClick={() => {
                            openMyModal();
                          }}
                          aria-hidden
                          className="hover:text-[#F59FB1] hover:cursor-pointer font-sans font-semibold text-black"
                        >
                          {smokingStyleText}
                        </span>
                        <div
                          onClick={() => {
                            openMyModal();
                          }}
                          aria-hidden
                        >
                          <img src={userarrow} alt="" className="w-3 ml-2" />
                        </div>
                      </div>
                    </div>
                  </div>
                  <hr />
                  <div className="flex justify-between m-3">
                    <div className="">
                      <span className="font-sans font-semibold text-black">
                        MBTI
                      </span>
                    </div>
                    <div>
                      <div className="flex items-center">
                        <span
                          onClick={() => {
                            openMyModal();
                          }}
                          aria-hidden
                          className="hover:text-[#F59FB1] hover:cursor-pointer font-sans font-semibold text-black"
                        >
                          {basicInfomation.MBTI}
                        </span>
                        <div
                          onClick={() => {
                            openMyModal();
                          }}
                          aria-hidden
                        >
                          <img src={userarrow} alt="" className="w-3 ml-2" />
                        </div>
                      </div>
                    </div>
                  </div>
                  <hr />
                  <div className="flex justify-between m-3">
                    <div className="">
                      <span className="font-sans font-semibold text-black">
                        관심사
                      </span>
                    </div>
                    <div
                      onClick={() => {
                        openMyModal3();
                      }}
                      aria-hidden
                    >
                      <div className="flex items-center hover:text-[#F59FB1]">
                        <span className="hover:cursor-pointer font-sans font-semibold text-black hover:text-[#F59FB1]">
                          설정
                        </span>

                        <div>
                          <img src={userarrow} alt="" className="w-3 ml-2" />
                        </div>
                      </div>
                    </div>
                  </div>
                  <hr />
                  <div className="flex justify-between m-3">
                    <div className="">
                      <span className="font-sans font-semibold text-black">
                        반려동물
                      </span>
                    </div>
                    <div>
                      <div className="flex items-center">
                        <span
                          onClick={() => {
                            openMyModal();
                          }}
                          aria-hidden
                          className="hover:text-[#F59FB1] hover:cursor-pointer font-sans font-semibold text-black"
                        >
                          {petText}
                        </span>
                        <div
                          onClick={() => {
                            openMyModal();
                          }}
                          aria-hidden
                        >
                          <img src={userarrow} alt="" className="w-3 ml-2" />
                        </div>
                      </div>
                    </div>
                  </div>
                  <hr />
                  <div className="flex justify-between m-3 mb-8">
                    <div className="">
                      <span className="font-sans font-semibold text-black">
                        병역여부
                      </span>
                    </div>
                    <div>
                      <div className="flex items-center">
                        <span
                          onClick={() => {
                            openMyModal();
                          }}
                          aria-hidden
                          className="hover:text-[#F59FB1] hover:cursor-pointer font-sans font-semibold text-black"
                        >
                          {militaryText}
                        </span>
                        <div
                          onClick={() => {
                            openMyModal();
                          }}
                          aria-hidden
                        >
                          <img src={userarrow} alt="" className="w-3 ml-2" />
                        </div>
                      </div>
                    </div>
                  </div>
                  <hr />
                </div>
                <hr className="thickhr" />

                <div className="text-2xl m-3 text-[#364C63]">
                  선호하는 상대정보
                </div>
                <div className="flex justify-between m-3 mt-8">
                  <div className="">
                    <span className="font-sans font-semibold text-black">
                      나이범위
                    </span>
                  </div>
                  <div>
                    <div className="flex items-center">
                      <span
                        onClick={() => {
                          openMyModal2();
                        }}
                        aria-hidden
                        className="hover:text-[#F59FB1] hover:cursor-pointer font-sans font-semibold text-black"
                      >
                        {' '}
                        {filterInfomation.age_min}
                        {' '}
                        -
                        {' '}
                        {filterInfomation.age_max}
                        {' '}
                        살
                      </span>
                      <div>
                        <img src={userarrow} alt="" className="w-3 ml-2" />
                      </div>
                    </div>
                  </div>
                </div>
                <hr />
                <div className="flex justify-between m-3">
                  <div className="">
                    <span className="font-sans font-semibold text-black">
                      키범위
                    </span>
                  </div>
                  <div>
                    <div className="flex items-center">
                      <span
                        onClick={() => {
                          openMyModal2();
                        }}
                        aria-hidden
                        className="hover:text-[#F59FB1] hover:cursor-pointer font-sans font-semibold text-black mr-1"
                      >
                        {filterInfomation.height_min}
                        {' '}
                        -
                        {' '}
                        {filterInfomation.height_max}
                        cm
                      </span>
                      <div>
                        <img src={userarrow} alt="" className="w-3 ml-2" />
                      </div>
                    </div>
                  </div>
                </div>
                <hr />
                <div className="flex justify-between m-3">
                  <div className="">
                    <span className="hover:text-[#F59FB1] hover:cursor-pointer font-sans font-semibold text-black">
                      거리 반경
                    </span>
                  </div>
                  <div>
                    <div className="flex items-center">
                      <span
                        onClick={() => {
                          openMyModal2();
                        }}
                        aria-hidden
                        className="hover:text-[#F59FB1] hover:cursor-pointer font-sans font-semibold text-black"
                      >
                        {' '}
                        {filterInfomation.range_min}
                        {' '}
                        -
                        {' '}
                        {filterInfomation.range_max}
                        {' '}
                        km
                      </span>
                      <div>
                        <img src={userarrow} alt="" className="w-3 ml-2" />
                      </div>
                    </div>
                  </div>
                </div>
                <hr />
                <div className="flex justify-between m-3">
                  <div className="">
                    <span className="font-sans font-semibold text-black">
                      연락 스타일
                    </span>
                  </div>
                  <div>
                    <div className="flex items-center">
                      <span
                        onClick={() => {
                          openMyModal2();
                        }}
                        aria-hidden
                        className="hover:text-[#F59FB1] hover:cursor-pointer font-sans font-semibold text-black"
                      >
                        {contactStyleText2}
                      </span>
                      <div>
                        <img src={userarrow} alt="" className="w-3 ml-2" />
                      </div>
                    </div>
                  </div>
                </div>
                <hr />
                <div className="flex justify-between m-3">
                  <div className="">
                    <span
                      onClick={() => {
                        openMyModal2();
                      }}
                      aria-hidden
                      className="font-sans font-semibold text-black"
                    >
                      음주 스타일
                    </span>
                  </div>
                  <div>
                    <div className="flex items-center">
                      <span
                        onClick={() => {
                          openMyModal2();
                        }}
                        aria-hidden
                        className="hover:text-[#F59FB1] hover:cursor-pointer font-sans font-semibold text-black"
                      >
                        {drinkingStyleText2}
                      </span>
                      <div>
                        <img src={userarrow} alt="" className="w-3 ml-2" />
                      </div>
                    </div>
                  </div>
                </div>
                <hr className="" />
                <div className="flex justify-between m-3">
                  <div className="">
                    <span className="font-sans font-semibold text-black">
                      흡연여부
                    </span>
                  </div>
                  <div>
                    <div className="flex items-center">
                      <span
                        onClick={() => {
                          openMyModal2();
                        }}
                        aria-hidden
                        className="hover:text-[#F59FB1] hover:cursor-pointer font-sans font-semibold text-black"
                      >
                        {smokingStyleText2}
                      </span>
                      <div>
                        <img src={userarrow} alt="" className="w-3 ml-2" />
                      </div>
                    </div>
                  </div>
                </div>
                <hr className="" />
                <div className="flex justify-between">
                  <span className="text-2xl m-3 text-[#364C63]">인증정보</span>
                  <div
                    onClick={toCert}
                    aria-hidden
                    className="flex items-center m-3"
                  >
                    <span className="hover:cursor-pointer font-sans font-semibold text-black hover:text-[#F59FB1]">
                      설정
                    </span>
                    <div>
                      <img src={userarrow} alt="" className="w-3 ml-2" />
                    </div>
                  </div>
                </div>

                <div className="mb-16">
                  <div className="my-5 ml-10 flex flex-wrap">
                    <div className="inline-block">
                      <Tooltip id="my-tooltip" />
                      <img
                        src={
                          newCertinfo.health !== false ? healthYes : healthNo
                        }
                        alt="#"
                        className="badges transition duration-500 hover:scale-110 bg-red-100 rounded-full"
                        data-tooltip-id="my-tooltip"
                        data-tooltip-content={`${
                          newCertinfo.health
                            ? newCertinfo.health_info
                            : '정보 없음'
                        }`}
                      />
                    </div>
                    <div className="inline-block">
                      <img
                        src={
                          newCertinfo.university !== false
                            ? universityYes
                            : universityNo
                        }
                        alt="#"
                        className="badges transition duration-500 hover:scale-110 bg-red-100 rounded-full"
                        data-tooltip-id="my-tooltip"
                        data-tooltip-content={`${
                          newCertinfo.university
                            ? newCertinfo.university_name
                            : '정보 없음'
                        }`}
                      />
                    </div>
                    <div className="inline-block">
                      <img
                        src={newCertinfo.job !== false ? jobYes : jobNo}
                        alt="#"
                        className="badges transition duration-500 hover:scale-110 bg-red-100 rounded-full"
                        data-tooltip-id="my-tooltip"
                        data-tooltip-content={`${
                          newCertinfo.job ? newCertinfo.job_name : '정보 없음'
                        }`}
                      />
                    </div>
                    <div className="inline-block">
                      <img
                        src={
                          newCertinfo.certificate !== false
                            ? certificateYes
                            : certificateNo
                        }
                        alt="#"
                        className="badges transition duration-500 hover:scale-110 bg-red-100 rounded-full"
                        data-tooltip-id="my-tooltip"
                        data-tooltip-content={`${
                          newCertinfo.certificate
                            ? newCertinfo.certificate_names
                            : '정보 없음'
                        }`}
                      />
                    </div>
                    <div className="inline-block">
                      <img
                        src={
                          newCertinfo.estate !== false ? estateYes : estateNo
                        }
                        alt="#"
                        className="badges transition duration-500 hover:scale-110 bg-red-100 rounded-full"
                        data-tooltip-id="my-tooltip"
                        data-tooltip-content={`${
                          newCertinfo.estate
                            ? newCertinfo.estate_amount
                            : '정보 없음'
                        }`}
                      />
                    </div>
                    <div className="inline-block">
                      <img
                        src={
                          newCertinfo.income !== false ? incomeYes : incomeNo
                        }
                        alt="#"
                        className="badges transition duration-500 hover:scale-110 bg-red-100 rounded-full"
                        data-tooltip-id="my-tooltip"
                        data-tooltip-content={`${
                          newCertinfo.income
                            ? newCertinfo.income_amount
                            : '정보 없음'
                        }`}
                      />
                    </div>
                  </div>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>
      <Navbar profileNav />
    </div>
  );
}

export default MyProfile;

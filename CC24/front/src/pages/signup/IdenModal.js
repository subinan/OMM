/* eslint-disable */

import React, { useState, useEffect } from 'react';
import CloseBtn from '../../assets/CloseBtn.svg';
import './IdenModal.css';
import { useSelector, useDispatch } from 'react-redux';
import { idInfo } from '../../store/userSlice';
import http from '../../api/fastapi';

function IdenModal({
  setIdenModal,
  setIdenComplete,
  inputday,
  inputname,
  inputyear,
  inputmonth,
  inputgender,
}) {
  const [imageSrc, setImageSrc] = useState('');
  const [imgfile, setFile] = useState('');
  const [name, setName] = useState('');
  const [gender, setGender] = useState('');
  const [birthday, setBirthday] = useState('');
  const [msg, setmessage] = useState('');
  const dispatch = useDispatch();

  // fastapi의 idening를 실행시키기 위한 코드
  async function sendImg() {
    const formData = new FormData();
    formData.append('inputday', inputday);
    formData.append('inputname', inputname);
    formData.append('inputyear', inputyear);
    formData.append('inputmonth', inputmonth);
    formData.append('inputgender', inputgender);
    formData.append('file', imgfile);
    await http({
      method: 'post',
      url: '/idenimg',
      data: formData,
      headers: {
        'Content-Type': 'multipart/form-data',
      },
    })
      .then((res) => {
        setmessage(res.data.message);
        setName(res.data.personalId.name);
        setBirthday(res.data.personalId.birthdate);
        setGender(res.data.personalId.gender);
        dispatch(idInfo(res.data));
      })
      .catch((err) => {
        console.log(err);
        console.log('fastapi로 이미지를 보내는데 실패했습니다.');
      });
  }

  const encodeFileToBase64 = (fileBlob) => {
    const reader = new FileReader();
    reader.readAsDataURL(fileBlob);
    setFile(fileBlob);
    return new Promise((resolve) => {
      reader.onload = () => {
        setImageSrc(reader.result);
        resolve();
      };
    });
  };
  // 데이터가 변경되면 재렌더링 되게 하는 코드
  useEffect(() => {
    if (imgfile) {
      sendImg();
    }
  }, [imgfile]);
  const handleFileInputChange = async (event) => {
    const file = event.target.files[0];
    await encodeFileToBase64(file);
    const formData = new FormData();
    formData.append('file', file);
  };

  return (
    <div className="flex-col mx-auto">
      <p className="flex justify-end">
        <img
          onClick={() => setIdenModal(false)}
          src={CloseBtn}
          className="w-8 h-8"
          alt="닫기"
        />
      </p>
      <br />
      <br />
      <div>
        <p className="text-3xl text-left ml-9 leading-relaxed" style={{ marginLeft: '1rem' }}>
          본인
        </p>
      </div>
      <div>
        <p className="text-3xl text-left ml-9 leading-relaxed" style={{ marginLeft: '1rem' }}>
          확인
        </p>
        <h4 className="ml-3 mt-5">주민등록증 사진을 올려주세요.</h4>
        <br />
      </div>
      <div className="mx-auto text-center flex">
        <div className="mx-auto mt-3">
          {!imageSrc && (
            <label htmlFor="imginput">
              <div className="fileinput" />
            </label>
          )}
          <input
            id="imginput"
            type="file"
            style={{ display: 'none' }}
            onChange={handleFileInputChange}
          />
        </div>
      </div>
      <div>
        {imageSrc && <img src={imageSrc} alt="preview-img"  className="max-w-xs mx-auto mt-3" />}
      </div>
      <br />
      <div className='mx-auto'>
        {imageSrc && (
          <Result
            data={{
              name,
              gender,
              birthday,
              msg
            }}
            setIdenModal={setIdenModal}
            setIdenComplete={setIdenComplete}
          />
        )}
      </div>
    </div>
  );
}

function Result({ data, setIdenModal, setIdenComplete }) {
  let { name, gender, birthday, msg } = data;
  const strbirth = String(birthday);
  let year = strbirth.slice(0, 4);
  let month = strbirth.slice(5, 7);
  if (month.slice(0, 1) == '0') {
    month = month.slice(1, 2);
  }
  let day = strbirth.slice(8, 10);
  if (day.slice(0, 1) == '0') {
    day = day.slice(1, 2);
  }
  if (gender == 'MALE') {
    gender = '남';
  } else {
    gender = '여';
  }
  const storeName = useSelector((state) => state.user.name);
  const storeYear = useSelector((state) => state.user.year);
  const storeMonth = useSelector((state) => state.user.month);
  const storeDay = useSelector((state) => state.user.day);
  const storeGender = useSelector((state) => state.user.gender);
  // 일치 여부 확인
  let nameCheck = false;
  let birthdayCheck = false;
  let genderCheck = false;
  if (name == storeName) {
    nameCheck = true;
  }
  if (gender == storeGender) {
    genderCheck = true;
  }
  if (storeYear == year && storeMonth == month && storeDay == day) {
    birthdayCheck = true;
  }
  // 모두 일치하면 확인 완료 버튼 활성화
  let complete = false;
  if (nameCheck && genderCheck && birthdayCheck) {
    complete = true;
  }
  return (
    <div className="max-w-xs mx-auto mt-3">
      <div className="flex mx-5 justify-between">
        <div>
          <div className='mx-auto text-center'>
            <p className='ml-12 text-center'>{msg}</p>
          </div>
          <span className="keys">이름</span>
          <img src="../../../Vector76.png" alt="#" className="inline ml-2" />
        </div>
        <div>
          <span>{name}</span>
          {nameCheck && <img src="../../../check.png" alt="#" className="ml-3 inline" />}
        </div>
      </div>

      <div className="flex mx-5 justify-between">
        <div>
          <span className="keys">성별</span>
          <img src="../../../Vector76.png" alt="#" className="inline ml-2" />
        </div>
        <div>
          <span>{gender}</span>
          {genderCheck && <img src="../../../check.png" alt="#" className="ml-3 inline" />}
        </div>
      </div>
      <div className="flex mx-5 justify-between">
        <div>
          <span className="keys">생년월일</span>
          <img src="../../../Vector76.png" alt="#" className="inline ml-2" />
        </div>
        <div>
          <span>
            {year}년 {month}월 {day}일
          </span>
          {birthdayCheck && <img src="../../../check.png" alt="#" className="ml-3 inline" />}
        </div>
      </div>
      <div className="mx-auto text-center">
        <div>
          {complete && (
            <button
              className="btn-active"
              onClick={() => {
                setIdenComplete(true);
                setIdenModal(false);
              }}
            >
              확인 완료
            </button>
          )}
        </div>
        <div>{!complete && <button className="btn-inactive">확인 완료</button>}</div>
      </div>
    </div>
  );
}

export default IdenModal;

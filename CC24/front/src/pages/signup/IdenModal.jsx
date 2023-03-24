import React, { useState } from 'react';
import CloseBtn from '../../assets/CloseBtn.svg';
import './index.css';
// import './FaceRecogModal.css';

import React, { useState, useEffect } from 'react';
import CloseBtn from '../../assets/CloseBtn.svg';
import './index.css';
import './FaceRecogModal.css';
import './IdenModal.css';
import Idenconfirm1 from '../../assets/Idenconfirm1.svg';
import Idenconfirm2 from '../../assets/Idenconfirm2.svg';
// import fastapi from '../../api/fastapi.js';
import axios from 'axios';

function IdenModal({ setIdenModal, setIdenComplete, name, year, month, day, gender }) {
  const [imageSrc, setImageSrc] = useState('');
  const [imgfile, setFile] = useState('');
  const [name, setName] = useState('');
  const [gender, setGender] = useState('');
  const [birthday, setBirthday] = useState('');
  const [completed, setBtn] = useState(false);

  // fastapi의 idening를 실행시키기 위한 코드
  async function sendImg() {
    console.log(imgfile);
    await axios({
      method: 'post',
      url: 'http://127.0.0.1:8000/idenimg',
      data: {
        // 데이터의 파일부분에 문제가 있는 것 같다.
        file: imgfile,
      },
      headers: {
        'Content-Type': 'multipart/form-data',
      },
    })
      .then((res) => {
        console.log(res.data);
        setName(res.data.name);
        setBirthday(res.data.birthday);
        setGender(res.data.gender);
        console.log('fastapi로이미지를 보냈습니다.');
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
        setBtn(true);
        setIdenComplete(true);
        resolve();
      };
    });
  };
  // 데이터가 변경되면 재렌더링 되게 하는 코드
  useEffect(() => {
    sendImg();
  }, [imgfile]);
  const handleFileInputChange = async (event) => {
    const file = event.target.files[0];

    await encodeFileToBase64(file);

    // fastapi/iden_img에 이미지를 저장하는 코드를 써야한다.
    const formData = new FormData();
    formData.append('file', file);
    // const { data } = await fastapi.get('/');

    // fastapi.post('/idenimg', { file: imgfile });
    // const { data } = await fastapi.post('/ocr');

    // console.log(data); // 처리 결과 출력
    // const { data } = await fastapi.post('/ocr', { path });
  };

  return (
    <div className="flex-col w-80 mx-auto">
      <p className="flex">
        <img src={CloseBtn} className="w-8 h-8 ml-auto mt-2" alt="닫기" />
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
        <br />
      </div>

      <div>
        {/* <img src="/public/upload.png" alt="Upload" /> */}
      </div>
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
      {/* <div>
        <div>
          <img src={Idenconfirm1} alt="Idenconfirm1" className="confirmbtn" />
        </div>
      </div> */}

      <div className="preview" style={{ marginLeft: '2rem' }}>
        {imageSrc && <img src={imageSrc} alt="preview-img" className="idenimage" />}
      </div>
      <br />
      <div>{imageSrc && (<Result data={{ name, gender, birthday }} />)}</div>
      <div>{imageSrc && <img src={Idenconfirm2} alt="Idenconfirm2" className="confirmbtn" />}</div>
      <div>
        {!imageSrc && <img src={Idenconfirm1} alt="Idenconfirm1" className="confirmbtn" />}

      </div>
      <div />

    </div>
  );
}

function Result(props) {
  const { name, gender, birthday } = props.data;
  const strbirth = String(birthday);
  const year = strbirth.slice(0, 2);
  const month = strbirth.slice(2, 4);
  const day = strbirth.slice(4, 6);
  return (

    <div style={{ marginLeft: '3rem' }}>
      <div className="parent">
        <span className="keys">이름</span>
        <img src="/public/Vector76.png" alt="#" className="vector76" />
        <span>{ name }</span>
        {/* 회원가입창에서 가져온 값과 일치할때만 체크 표시 보여주기? */}
        <img src="/public/check.png" alt="#" className="check" />
      </div>

      <div className="parent">
        <span className="keys">성별</span>
        <img src="/public/Vector76.png" alt="#" className="vector76" />
        <span>
          {gender === 1 ? '남' : '여'}
        </span>
        <img src="/public/check.png" alt="#" className="check" />
      </div>
      <div className="parent">
        <span className="keys">생년월일</span>
        <img src="/public/Vector76.png" alt="#" className="vector76" />
        {/* <span>{birthday}</span> */}
        <span>
          {year}
          년
          {' '}
          {month}
          월
          {' '}
          {day}
          일
        </span>

        <img src="/public/check.png" alt="#" className="check" />
      </div>

    </div>
  );
}

export default IdenModal;

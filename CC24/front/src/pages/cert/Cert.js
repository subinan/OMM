/*eslint-disable*/
import React, { useState, useEffect } from 'react';
import Modal from 'react-modal';
import axios from '../../api/springapi';
import './Cert.css';
import CC24Logo from '../../assets/CC24.svg';
import CertModal from './CertModal';
import Navbar from '../../components/Navbar';

function Cert() {
  const [modal, setModal] = useState(false);
  const [cert, setCert] = useState('');
  const [info, setInfo] = useState(null);

  async function getList(select) {
    await axios({
      method: 'get',
      url: `cert/${select}`,
    })
      .then((res) => {
        console.log(res);
        setInfo(res);
        setModal(true);
      })
      .catch((err) => {
        console.log(err);
        setModal(true);
      });
  }
  return (
    <div className="flex mt-20">
      <div className="w-80 mx-auto">
        <img src={CC24Logo} className="cert-title" alt="CC24 logo" />
        <Modal
          isOpen={modal}
          onRequestClose={() => setModal(false)}
          ariaHideApp={false}
          className="Modal"
          overlayClassName="Overlay"
        >
          <CertModal
            cert={cert}
            info={info}
            isClose={(res) => {
              if (res) {
                setModal(false);
              }
            }}
          />
        </Modal>
        <div
          onClick={() => {
            setCert('대학교');
            getList('university');
          }}
          aria-hidden="true"
          className="flex justify-between py-3 border-b-2 border-b-gray-200 hover:bg-gray-100"
        >
          <div className="text-xl hover:text-blue-900">대학교 인증</div>
          <div className="cert-point text-xl hover:text-stone-900"> &gt;</div>
        </div>
        <div
          onClick={() => {
            setCert('회사');
            getList('job');
          }}
          aria-hidden="true"
          className="flex justify-between py-3 border-b-2 border-b-gray-200 hover:bg-gray-100"
        >
          <div className="text-xl hover:text-blue-900">회사 인증</div>
          <div className="cert-point text-xl hover:text-stone-900"> &gt;</div>
        </div>
        <div
          onClick={() => {
            setCert('소득');
            setModal(true);
          }}
          aria-hidden="true"
          className="flex justify-between py-3 border-b-2 border-b-gray-200 hover:bg-gray-100"
        >
          <div className="text-xl hover:text-blue-900">소득 인증</div>
          <div className="cert-point text-xl hover:text-stone-900"> &gt;</div>
        </div>
        <div
          onClick={() => {
            setCert('부동산');
            setModal(true);
          }}
          aria-hidden="true"
          className="flex justify-between py-3 border-b-2 border-b-gray-200 hover:bg-gray-100"
        >
          <div className="text-xl hover:text-blue-900">부동산 인증</div>
          <div className="cert-point text-xl hover:text-stone-900"> &gt;</div>
        </div>
        <div
          onClick={() => {
            setCert('건강검진서');
            setModal(true);
          }}
          aria-hidden="true"
          className="flex justify-between py-3 border-b-2 border-b-gray-200 hover:bg-gray-100"
        >
          <div className="text-xl hover:text-blue-900">건강검진서</div>
          <div className="cert-point text-xl hover:text-stone-900"> &gt;</div>
        </div>
        <div
          onClick={() => {
            setCert('자격증');
            getList('certificate');
          }}
          aria-hidden="true"
          className="flex justify-between py-3 border-b-2 border-b-gray-200 hover:bg-gray-100"
        >
          <div className="text-xl hover:text-blue-900">자격증 인증</div>
          <div className="cert-point text-xl hover:text-stone-900"> &gt;</div>
        </div>
        <Navbar className="fixed" />
      </div>
    </div>
  );
}

export default Cert;

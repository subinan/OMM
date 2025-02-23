/* eslint-disable */
import React, { useCallback, useState, useEffect } from 'react';
import { createVerifiablePresentationJwt } from 'did-jwt-vc';
import { useSelector } from 'react-redux';
import { EthrDID } from 'ethr-did';
import ommapi from '../../api/ommapi';

function Agree({ setIsLoading }) {
  const [checkedList, setCheckedList] = useState([]);
  const [isChecked, setIsChecked] = useState(false);
  const searchParams = new URLSearchParams(window.location.search);
  const type = searchParams.get('type');
  const idvc = JSON.parse(localStorage.getItem('IdenVC'));
  const didvc = JSON.parse(localStorage.getItem('DIDvc'));
  const [did, setDid] = useState(null);
  const [iden, setIden] = useState(null);
  const [pk, setPK] = useState(null);
  const [ethrDidOnGoerliNamed, setEthrDidOnGoerliNamed] = useState(null);
  useEffect(() => {
    if (localStorage.getItem('DID')) {
      setDid(JSON.parse(localStorage.getItem('DID')).did);
      setIden(JSON.parse(localStorage.getItem('keypair')).identifier);
      setPK(JSON.parse(localStorage.getItem('keypair')).privateKey);
      const ethrDidOnGoerli = new EthrDID({
        identifier: JSON.parse(localStorage.getItem('keypair')).identifier,
        privateKey: JSON.parse(localStorage.getItem('keypair')).privateKey,
        chainNameOrId: 'goerli',
      });
      setEthrDidOnGoerliNamed(ethrDidOnGoerli);
    }
  }, []);

  const checkedItemHandler = (value: string, isChecked: boolean) => {
    if (isChecked) {
      setCheckedList((prev) => [...prev, value]);
      return;
    }
    if (!isChecked && checkedList.includes(value)) {
      setCheckedList(checkedList.filter((item) => item !== value));
      return;
    }
    return;
  };
  const checkHandler = (e: React.ChangeEvent<HTMLInputElement>) => {
    setIsChecked(!isChecked);
    checkedItemHandler(e.target.checked);
  };

  const toOMM = async () => {
    const vpPayload = {
      vp: {
        '@context': ['https://www.w3.org/2018/credentials/v1'],
        type: ['VerifiablePresentation', 'PersonalIdPresentation'],
        verifiableCredential: [idvc, didvc],
      },
    };
    const vpJwt = await createVerifiablePresentationJwt(vpPayload, ethrDidOnGoerliNamed);
    const data = {
      type: type,
      holderDid: did,
      vpJwt: vpJwt,
    };
    if (isChecked) {
      setIsLoading(true);
      await ommapi
        .post(`/sign/${type}`, data)
        .then((res) => {
          console.log(res);

          setIsLoading(false);
          window.location.href = res.data;
        })
        .catch((err) => {
          console.log(err);
        });
    } else {
      alert('동의해 주세요.');
    }
  };
  return (
    <div className="wrap-box">
      <div className="flex-col w-80 mx-auto">
        <p className="text-3xl text-left mb-4 leading-relaxed">
          정보
          <br />
          제공
          <br />
          동의
          {checkedList}
        </p>
        <p className="text-xl mt-10 mb-4 leading-relaxed text-center text-blue-800">
          이름, 나이, 성별, 사진
        </p>
        <p className="text-lg mb-4 leading-relaxed px-10">
          개인정보 제공에 동의해야만 OMM 서비스를 이용할 수 있습니다.
        </p>
      </div>
      <div className="flex-col w-80 mx-auto text-center content-center">
        <p className="flex-col my-auto text-lg inline">동의하시겠습니까?</p>
        <input
          value="동의"
          type="checkbox"
          onChange={(e) => {
            checkHandler(e);
          }}
          className="w-4 h-4 inline ml-2 text-blue-800 bg-gray-100 border-gray-300 rounded focus:ring-blue-500 dark:focus:ring-blue-600 dark:ring-offset-gray-700 dark:focus:ring-offset-gray-700 focus:ring-2 dark:bg-gray-600 dark:border-gray-500"
        />
      </div>
      <div className="mx-auto mt-10 text-center">
        {!isChecked && (
          <button disabled type="button" className="btn">
            OMM 회원 가입
          </button>
        )}
        {isChecked && (
          <button onClick={toOMM} type="button" className="btn">
            OMM 회원 가입
          </button>
        )}
      </div>
    </div>
  );
}

export default Agree;

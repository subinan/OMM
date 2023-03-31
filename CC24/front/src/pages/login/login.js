/* eslint-disable */
import React, { useState } from 'react';
import Modal from 'react-modal';
import Password from './Password';
import Agree from './Agree';
import { useNavigate } from 'react-router-dom';
import ommapi from '../../api/ommapi';

function Login() {
  const navigate = useNavigate();
  const searchParams = new URLSearchParams(window.location.search);
  const type = searchParams.get('type');
  const did = JSON.parse(localStorage.getItem('DID')).did;
  console.log(did);
  const data = {
    holderDid: did,
    vpJwt:
      'eyJhbGciOiJFUzI1NkstUiIsInR5cCI6IkpXVCJ9.eyJ2cCI6eyJAY29udGV4dCI6WyJodHRwczovL3d3dy53My5vcmcvMjAxOC9jcmVkZW50aWFscy92MSJdLCJ0eXBlIjpbIlZlcmlmaWFibGVQcmVzZW50YXRpb24iXSwidmVyaWZpYWJsZUNyZWRlbnRpYWwiOlsiZXlKaGJHY2lPaUpGVXpJMU5rc3RVaUlzSW5SNWNDSTZJa3BYVkNKOS5leUpsZUhBaU9qRTJPREkzTlRjMU9USXNJblpqSWpwN0lrQmpiMjUwWlhoMElqcGJJbWgwZEhCek9pOHZkM2QzTG5jekxtOXlaeTh5TURFNEwyTnlaV1JsYm5ScFlXeHpMM1l4SWwwc0luUjVjR1VpT2xzaVZtVnlhV1pwWVdKc1pVTnlaV1JsYm5ScFlXd2lMQ0pRWlhKemIyNWhiRWxrUTNKbFpHVnVkR2xoYkNKZExDSmpjbVZrWlc1MGFXRnNVM1ZpYW1WamRDSTZleUp3WlhKemIyNWhiRWx1Wm04aU9uc2libUZ0WlNJNkl1cTVnT3ljcE91dnVDSXNJbUpwY25Sb1pHRjBaU0k2SWpFNU9Ua3RNVEV0TVRZaUxDSm5aVzVrWlhJaU9pSkdSVTFCVEVVaWZYMTlMQ0p6ZFdJaU9pSmthV1E2WlhSb2NqcG5iMlZ5YkdrNk1IZ3dNMlJtT0dVMU5HRXpNR1V6T1RBMlpESTBNMlEzTkRBeVl6VTVZamd5WWpWa09EVTBNakl6WW1FellXVTVOamxsWVRJelpESmpNVEppT0dSaE5EbGpOV1VpTENKcGMzTWlPaUprYVdRNlpYUm9janBuYjJWeWJHazZNSGd3TXpBM1pqUmtPRFUzTVdSa056WmpOakZqTUdJMVl6aGxaV1ppT0RBMU4yVTRORGxqWWpjd1pUSXdNV014WWpCa016TXhaV1U1Tnpaa09UVXpOMkkzTTJJaWZRLng5Qnd6bFpjSDhTd21NeXJDbzdVZFdpNUIzZW1WSldaZWJ0RHd6ZGlJNldsd1drSW9BVW56dC12SmxxVnZnOFo0amZNYTRnR3BZM3JWUnhiNlFCQjJBQSJdfSwiaXNzIjoiZGlkOmV0aHI6Z29lcmxpOjB4MDNkZjhlNTRhMzBlMzkwNmQyNDNkNzQwMmM1OWI4MmI1ZDg1NDIyM2JhM2FlOTY5ZWEyM2QyYzEyYjhkYTQ5YzVlIn0.aaQ-BH_yEonZanA95Afb2yRGHbNMLfpXwymvPYywWRr3Iq8fl8qmAWdT-97btV21jNNDgA1XBTccqZM5_rIa5wA',
  };
  console.log(data);
  if (!localStorage.getItem('VC')) {
    navigate('/signup');
  }
  const ommLogin = async () => {
    await ommapi
      .post(`sign/${type}`, {
        holderDid: did,
        vpJwt:
          'eyJhbGciOiJFUzI1NkstUiIsInR5cCI6IkpXVCJ9.eyJ2cCI6eyJAY29udGV4dCI6WyJodHRwczovL3d3dy53My5vcmcvMjAxOC9jcmVkZW50aWFscy92MSJdLCJ0eXBlIjpbIlZlcmlmaWFibGVQcmVzZW50YXRpb24iXSwidmVyaWZpYWJsZUNyZWRlbnRpYWwiOlsiZXlKaGJHY2lPaUpGVXpJMU5rc3RVaUlzSW5SNWNDSTZJa3BYVkNKOS5leUpsZUhBaU9qRTJPREkzTlRjMU9USXNJblpqSWpwN0lrQmpiMjUwWlhoMElqcGJJbWgwZEhCek9pOHZkM2QzTG5jekxtOXlaeTh5TURFNEwyTnlaV1JsYm5ScFlXeHpMM1l4SWwwc0luUjVjR1VpT2xzaVZtVnlhV1pwWVdKc1pVTnlaV1JsYm5ScFlXd2lMQ0pRWlhKemIyNWhiRWxrUTNKbFpHVnVkR2xoYkNKZExDSmpjbVZrWlc1MGFXRnNVM1ZpYW1WamRDSTZleUp3WlhKemIyNWhiRWx1Wm04aU9uc2libUZ0WlNJNkl1cTVnT3ljcE91dnVDSXNJbUpwY25Sb1pHRjBaU0k2SWpFNU9Ua3RNVEV0TVRZaUxDSm5aVzVrWlhJaU9pSkdSVTFCVEVVaWZYMTlMQ0p6ZFdJaU9pSmthV1E2WlhSb2NqcG5iMlZ5YkdrNk1IZ3dNMlJtT0dVMU5HRXpNR1V6T1RBMlpESTBNMlEzTkRBeVl6VTVZamd5WWpWa09EVTBNakl6WW1FellXVTVOamxsWVRJelpESmpNVEppT0dSaE5EbGpOV1VpTENKcGMzTWlPaUprYVdRNlpYUm9janBuYjJWeWJHazZNSGd3TXpBM1pqUmtPRFUzTVdSa056WmpOakZqTUdJMVl6aGxaV1ppT0RBMU4yVTRORGxqWWpjd1pUSXdNV014WWpCa016TXhaV1U1Tnpaa09UVXpOMkkzTTJJaWZRLng5Qnd6bFpjSDhTd21NeXJDbzdVZFdpNUIzZW1WSldaZWJ0RHd6ZGlJNldsd1drSW9BVW56dC12SmxxVnZnOFo0amZNYTRnR3BZM3JWUnhiNlFCQjJBQSJdfSwiaXNzIjoiZGlkOmV0aHI6Z29lcmxpOjB4MDNkZjhlNTRhMzBlMzkwNmQyNDNkNzQwMmM1OWI4MmI1ZDg1NDIyM2JhM2FlOTY5ZWEyM2QyYzEyYjhkYTQ5YzVlIn0.aaQ-BH_yEonZanA95Afb2yRGHbNMLfpXwymvPYywWRr3Iq8fl8qmAWdT-97btV21jNNDgA1XBTccqZM5_rIa5wA',
      })
      .then((res) => {
        console.log(res);
      })
      .catch((err) => {
        console.log(err);
      });
  };

  const [passwordModal, setPasswordModal] = useState(true);
  const [passwordComplete, setPasswordComplete] = useState(true);
  console.log(passwordComplete);
  return (
    <div>
      <div className="flex-col w-80 mx-auto">
        <p className="text-3xl mt-10 text-center mb-4 leading-relaxed">로그인 중 ...</p>
      </div>
      {type == 'SIGNUP' && <Agree />}
      <div class="text-center">
        <div class="static" role="status">
          <img class="absolute top-[175px] left-[335px]" src="../../../ommheart.png"></img>
          <svg
            aria-hidden="true"
            class="inline w-[300px] h-[300px] mr-2 text-gray-200 animate-spin dark:text-gray-600 fill-blue-600"
            viewBox="0 0 100 101"
            fill="none"
            xmlns="http://www.w3.org/2000/svg"
          >
            <path
              d="M100 50.5908C100 78.2051 77.6142 100.591 50 100.591C22.3858 100.591 0 78.2051 0 50.5908C0 22.9766 22.3858 0.59082 50 0.59082C77.6142 0.59082 100 22.9766 100 50.5908ZM9.08144 50.5908C9.08144 73.1895 27.4013 91.5094 50 91.5094C72.5987 91.5094 90.9186 73.1895 90.9186 50.5908C90.9186 27.9921 72.5987 9.67226 50 9.67226C27.4013 9.67226 9.08144 27.9921 9.08144 50.5908Z"
              fill="currentColor"
            />
            <path
              d="M93.9676 39.0409C96.393 38.4038 97.8624 35.9116 97.0079 33.5539C95.2932 28.8227 92.871 24.3692 89.8167 20.348C85.8452 15.1192 80.8826 10.7238 75.2124 7.41289C69.5422 4.10194 63.2754 1.94025 56.7698 1.05124C51.7666 0.367541 46.6976 0.446843 41.7345 1.27873C39.2613 1.69328 37.813 4.19778 38.4501 6.62326C39.0873 9.04874 41.5694 10.4717 44.0505 10.1071C47.8511 9.54855 51.7191 9.52689 55.5402 10.0491C60.8642 10.7766 65.9928 12.5457 70.6331 15.2552C75.2735 17.9648 79.3347 21.5619 82.5849 25.841C84.9175 28.9121 86.7997 32.2913 88.1811 35.8758C89.083 38.2158 91.5421 39.6781 93.9676 39.0409Z"
              fill="currentFill"
            />
          </svg>
          <span class="sr-only">Loading...</span>
        </div>
      </div>
      <Modal
        isOpen={passwordModal}
        // onRequestClose={() => setPasswordModal(false)}
        ariaHideApp={true}
        className="Modal"
        overlayClassName="Overlay"
      >
        <Password
          setPasswordModal={setPasswordModal}
          setPasswordComplete={(res) => {
            if (res) {
              setPasswordComplete(true);
              ommLogin();
            }
          }}
        />
      </Modal>
    </div>
  );
}

export default Login;

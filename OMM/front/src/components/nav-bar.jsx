import React, { useRef, useEffect } from 'react';
import SockJS from 'sockjs-client';
// import SockJS from 'sockjs-client/dist/sockjs';
import Stomp from 'stompjs';
import './nav-bar.scss';
import { Link } from 'react-router-dom';
import axios from '../api/http';

function Navbar({ profileNav, mainNav, notiNav, chatlistNav, likesNav }) {
  let stompClient;
  const headers = {
    Authorization: import.meta.env.VITE_TOKEN,
  };

  const mainconnect = () => {
    const ws = new SockJS('http://localhost:5000/api/matching');
    stompClient = Stomp.over(ws);
    stompClient.connect(
      headers,
      (frame) => {
        console.log('연결성공');
      },
      (error) => {
        // 연결이 끊어졌을 때 재연결 시도 부분
        // 필요할 때 쓰면 될 듯.
        // if(reconnect++ < 5) {
        //   setTimeout(function() {
        //     console.log("connection reconnect");
        //     connect();
        //   },10*1000);
        // }
      },
    );
  };
  const chatlistconnect = () => {
    const ws = new SockJS('http://localhost:5000/api/chat');
    stompClient = Stomp.over(ws);
    stompClient.connect(
      headers,
      (frame) => {
        console.log('연결성공');
      },
      (error) => {
        // 연결이 끊어졌을 때 재연결 시도 부분
        // 필요할 때 쓰면 될 듯.
        // if(reconnect++ < 5) {
        //   setTimeout(function() {
        //     console.log("connection reconnect");
        //     connect();
        //   },10*1000);
        // }
      },
    );
  };

  const sendMatch = () => {
    // redux 에서 첫번째사람 지우는 함수 작성
    // match 알림 보내기
    console.log(stompClient);
    stompClient.send(
      '/pub/matching/noti',
      headers,
      JSON.stringify({ receiverId: 1 }),
    );
    console.log(stompClient);
    // stompClient.disconnect();
  };
  // const sendMatch = async () => {
  //   await axios
  //     .get('member/1')
  //     .then((response) => {
  //       console.log(response.data);
  //     })
  //     .catch((error) => {
  //       console.log('에러 발생');
  //       console.log(error);
  //     });
  // };

  useEffect(() => {
    if (mainNav) {
      mainconnect();
    } else if (chatlistNav) {
      chatlistconnect();
    }
  });

  return (
    <div className="flex justify-center">
      <nav className="menu">
        <div className="menu-item">
          {!likesNav && (
            <Link to="/likes" className="menu-item">
              <i className="bi bi-search-heart transition duration-300 hover:scale-125" />
            </Link>
          )}
          {likesNav && <i className="bi bi-search-heart-fill" />}
        </div>
        <div className="menu-item">
          {!chatlistNav && (
            <Link
              to="/chattings"
              className="transition duration-300 hover:scale-125"
            >
              <i className="bi bi-chat-heart" />
            </Link>
          )}
          {chatlistNav && <i className="bi bi-chat-heart-fill" />}
        </div>
        {!mainNav && (
          <Link
            to="/main"
            className="flex w-16 h-16 transition duration-500 hover:scale-110 bg-red-100 rounded-full mx-auto my-auto shadow-md"
          >
            <img
              className="w-10 h-10 mx-auto my-auto"
              src="/pastelheart.png"
              alt=""
            />
          </Link>
        )}
        {mainNav && (
          <div className="flex w-16 h-16 transition duration-500 hover:scale-110 bg-red-100 rounded-full mx-auto my-auto shadow-md">
            <img
              className="w-10 h-10 mx-auto my-auto"
              src="/ommheart.png"
              alt=""
              onClick={() => {
                sendMatch();
              }}
              aria-hidden="true"
            />
          </div>
        )}
        <div className="menu-item">
          {notiNav && <i className="bi bi-bell-fill" />}
          {!notiNav && (
            <Link to="/notification" className="menu-item">
              <i className="bi bi-bell transition duration-300 hover:scale-125" />
            </Link>
          )}
        </div>
        <div className="menu-item">
          {!profileNav && (
            <Link to="/Myprofile" className="menu-item">
              <i className="bi bi-person transition duration-300 hover:scale-125" />
            </Link>
          )}
          {profileNav && <i className="bi bi-person-fill" />}
        </div>
      </nav>
    </div>
  );
}

export default Navbar;

/* eslint-disable */
import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';

function AlertModal({ setAlertModal, alertTitle, alertMessage }) {
  const navigate = useNavigate();
  const fn = () => {
    if (location.pathname === '/signup' || location.pathname === '/register') {
      setAlertModal(false);
    } else if (location.pathname === '/main') {
      window.localStorage.clear();
      navigate('/');
    }
  };
  return (
    <div className="flex-col mx-auto w-full">
      <div class="flex items-start justify-between p-4 border-b rounded-t dark:border-gray-600">
        <h3 class="text-xl font-semibold text-gray-900 dark:text-white">{alertTitle}</h3>
        <button
          type="button"
          onClick={() => {
            setAlertModal(false);
          }}
          class="text-gray-400 bg-transparent hover:bg-gray-200 hover:text-gray-900 rounded-lg text-sm p-1.5 ml-auto inline-flex items-center dark:hover:bg-gray-600 dark:hover:text-white"
          data-modal-hide="defaultModal"
        >
          <svg
            aria-hidden="true"
            class="w-5 h-5"
            fill="currentColor"
            viewBox="0 0 20 20"
            xmlns="http://www.w3.org/2000/svg"
          >
            <path
              fill-rule="evenodd"
              d="M4.293 4.293a1 1 0 011.414 0L10 8.586l4.293-4.293a1 1 0 111.414 1.414L11.414 10l4.293 4.293a1 1 0 01-1.414 1.414L10 11.414l-4.293 4.293a1 1 0 01-1.414-1.414L8.586 10 4.293 5.707a1 1 0 010-1.414z"
              clip-rule="evenodd"
            ></path>
          </svg>
        </button>
      </div>
      <div class="p-6 space-y-6">
        <p class="text-base leading-relaxed text-gray-500 dark:text-gray-400">{alertMessage}</p>
      </div>
      {location.pathname !== '/signup' && (
        <div class="flex items-center p-6 space-x-2 border-t border-gray-200 rounded-b dark:border-gray-600">
          <button
            onClick={() => {
              fn();
            }}
            type="button"
            class="text-white mx-auto bg-blue-700 hover:bg-blue-800 focus:ring-4 focus:outline-none focus:ring-blue-300 font-medium rounded-lg text-sm px-5 py-2.5 text-center dark:bg-blue-600 dark:hover:bg-blue-700 dark:focus:ring-blue-800"
          >
            확인
          </button>
        </div>
      )}
      <p className="text-3xl text-center ml-2 mt-2 leading-relaxed"></p>
    </div>
  );
}

export default AlertModal;

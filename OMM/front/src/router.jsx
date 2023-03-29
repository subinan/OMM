import React from 'react';
import { createBrowserRouter } from 'react-router-dom';
import FaceRecog from './pages/signup/FaceRecog';
import Index from './pages/index/Index';
import Signup from './pages/signup/Signup';
import MoreInfo from './pages/signup/MoreInfo';
import MoreInfo2 from './pages/signup/MoreInfo2';
import MoreInfo3 from './pages/signup/MoreInfo3';
import MoreInfo4 from './pages/signup/MoreInfo4';
import SignupComplete from './pages/signup/SignupComplete';
// import Login from './pages/login/Login';
import MyinfoSetModal from './pages/profile/MyinfoSetModal';
import OtherProfile from './pages/profile/OtherProfile';
import MyProfile from './pages/profile/MyProfile';
import Main from './pages/main/Main';
import Admin from './pages/admin/Admin';
import Detail from './pages/admin/Detail';

const router = createBrowserRouter([
  {
    path: '/',
    element: <Index />,
  },
  {
    path: '/faceRecog',
    element: <FaceRecog />,
  },
  {
    path: '/signup',
    element: <Signup />,
  },
  {
    path: '/OtherProfile',
    element: <OtherProfile />,
  },
  {
    path: '/MyinfoSetModal',
    element: <MyinfoSetModal />,
  },
  {
    path: '/moreinfo',
    element: <MoreInfo />,
  },
  {
    path: '/moreinfo/2',
    element: <MoreInfo2 />,
  },
  {
    path: '/main',
    element: <Main />,
  },
  {
    path: '/moreinfo/3',
    element: <MoreInfo3 />,
  },
  {
    path: '/MyProfile',
    element: <MyProfile />,
  },
  {
    path: '/moreinfo/4',
    element: <MoreInfo4 />,
  },
  {
    path: '/signupcomplete',
    element: <SignupComplete />,
  },
  {
    path: '/admin',
    element: <Admin />,
  },
  {
    path: '/admin/detail/:id',
    element: <Detail />,
  },
]);

export default router;

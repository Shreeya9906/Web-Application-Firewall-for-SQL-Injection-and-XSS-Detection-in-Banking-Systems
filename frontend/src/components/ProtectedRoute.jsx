import { useState, useEffect } from 'react';
import { Navigate, Outlet } from 'react-router-dom';
import { getMe } from '../services/api';
import Loading from './Loading';

export default function ProtectedRoute() {
  const [auth, setAuth] = useState(null);

  useEffect(() => {
    getMe()
      .then(res => setAuth(res.data.authenticated))
      .catch(() => setAuth(false));
  }, []);

  if (auth === null) return <Loading />;
  return auth ? <Outlet /> : <Navigate to="/login" />;
}

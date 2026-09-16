rule TTP_XOR_QUAD_CurrentVersionRun_43a9 {
  strings:
    $key_43a9 = { 10 c6 [2] 34 c8 [2] 1f e4 [2] 31 c6 [2] 25 dd [2] 2a c7 [2] 34 da [2] 36 db [2] 2d dd [2] 31 da [2] 2d f5 }

  condition:
    any of them
}
rule TTP_XOR_QUAD_CurrentVersionRun_4ba9 {
  strings:
    $key_4ba9 = { 18 c6 [2] 3c c8 [2] 17 e4 [2] 39 c6 [2] 2d dd [2] 22 c7 [2] 3c da [2] 3e db [2] 25 dd [2] 39 da [2] 25 f5 }

  condition:
    any of them
}
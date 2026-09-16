rule TTP_XOR_QUAD_CurrentVersionRun_2ba9 {
  strings:
    $key_2ba9 = { 78 c6 [2] 5c c8 [2] 77 e4 [2] 59 c6 [2] 4d dd [2] 42 c7 [2] 5c da [2] 5e db [2] 45 dd [2] 59 da [2] 45 f5 }

  condition:
    any of them
}
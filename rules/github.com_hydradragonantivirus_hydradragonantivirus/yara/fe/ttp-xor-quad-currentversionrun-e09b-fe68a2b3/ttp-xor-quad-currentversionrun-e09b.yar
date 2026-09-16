rule TTP_XOR_QUAD_CurrentVersionRun_e09b {
  strings:
    $key_e09b = { b3 f4 [2] 97 fa [2] bc d6 [2] 92 f4 [2] 86 ef [2] 89 f5 [2] 97 e8 [2] 95 e9 [2] 8e ef [2] 92 e8 [2] 8e c7 }

  condition:
    any of them
}
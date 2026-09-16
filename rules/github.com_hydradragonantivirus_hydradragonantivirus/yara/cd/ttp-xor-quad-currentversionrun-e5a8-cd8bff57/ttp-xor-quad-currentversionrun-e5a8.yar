rule TTP_XOR_QUAD_CurrentVersionRun_e5a8 {
  strings:
    $key_e5a8 = { b6 c7 [2] 92 c9 [2] b9 e5 [2] 97 c7 [2] 83 dc [2] 8c c6 [2] 92 db [2] 90 da [2] 8b dc [2] 97 db [2] 8b f4 }

  condition:
    any of them
}
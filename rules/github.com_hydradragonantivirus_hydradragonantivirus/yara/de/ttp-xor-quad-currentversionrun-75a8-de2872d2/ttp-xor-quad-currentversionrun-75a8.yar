rule TTP_XOR_QUAD_CurrentVersionRun_75a8 {
  strings:
    $key_75a8 = { 26 c7 [2] 02 c9 [2] 29 e5 [2] 07 c7 [2] 13 dc [2] 1c c6 [2] 02 db [2] 00 da [2] 1b dc [2] 07 db [2] 1b f4 }

  condition:
    any of them
}
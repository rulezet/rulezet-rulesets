rule TTP_XOR_QUAD_CurrentVersionRun_c9b7 {
  strings:
    $key_c9b7 = { 9a d8 [2] be d6 [2] 95 fa [2] bb d8 [2] af c3 [2] a0 d9 [2] be c4 [2] bc c5 [2] a7 c3 [2] bb c4 [2] a7 eb }

  condition:
    any of them
}
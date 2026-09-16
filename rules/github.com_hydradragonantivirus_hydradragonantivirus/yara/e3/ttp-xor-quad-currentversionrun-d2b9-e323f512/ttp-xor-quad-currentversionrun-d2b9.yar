rule TTP_XOR_QUAD_CurrentVersionRun_d2b9 {
  strings:
    $key_d2b9 = { 81 d6 [2] a5 d8 [2] 8e f4 [2] a0 d6 [2] b4 cd [2] bb d7 [2] a5 ca [2] a7 cb [2] bc cd [2] a0 ca [2] bc e5 }

  condition:
    any of them
}
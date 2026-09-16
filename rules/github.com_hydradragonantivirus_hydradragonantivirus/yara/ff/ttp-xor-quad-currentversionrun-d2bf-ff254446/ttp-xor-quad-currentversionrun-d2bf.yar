rule TTP_XOR_QUAD_CurrentVersionRun_d2bf {
  strings:
    $key_d2bf = { 81 d0 [2] a5 de [2] 8e f2 [2] a0 d0 [2] b4 cb [2] bb d1 [2] a5 cc [2] a7 cd [2] bc cb [2] a0 cc [2] bc e3 }

  condition:
    any of them
}
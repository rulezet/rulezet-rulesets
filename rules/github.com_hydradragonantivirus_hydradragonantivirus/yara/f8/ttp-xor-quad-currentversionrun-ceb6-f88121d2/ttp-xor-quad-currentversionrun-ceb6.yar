rule TTP_XOR_QUAD_CurrentVersionRun_ceb6 {
  strings:
    $key_ceb6 = { 9d d9 [2] b9 d7 [2] 92 fb [2] bc d9 [2] a8 c2 [2] a7 d8 [2] b9 c5 [2] bb c4 [2] a0 c2 [2] bc c5 [2] a0 ea }

  condition:
    any of them
}
rule TTP_XOR_QUAD_CurrentVersionRun_cec6 {
  strings:
    $key_cec6 = { 9d a9 [2] b9 a7 [2] 92 8b [2] bc a9 [2] a8 b2 [2] a7 a8 [2] b9 b5 [2] bb b4 [2] a0 b2 [2] bc b5 [2] a0 9a }

  condition:
    any of them
}
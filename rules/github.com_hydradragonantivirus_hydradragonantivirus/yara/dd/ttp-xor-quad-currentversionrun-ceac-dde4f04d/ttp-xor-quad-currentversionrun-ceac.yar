rule TTP_XOR_QUAD_CurrentVersionRun_ceac {
  strings:
    $key_ceac = { 9d c3 [2] b9 cd [2] 92 e1 [2] bc c3 [2] a8 d8 [2] a7 c2 [2] b9 df [2] bb de [2] a0 d8 [2] bc df [2] a0 f0 }

  condition:
    any of them
}
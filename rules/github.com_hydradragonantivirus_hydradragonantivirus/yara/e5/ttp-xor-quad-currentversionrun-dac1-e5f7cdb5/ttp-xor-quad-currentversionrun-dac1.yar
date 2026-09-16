rule TTP_XOR_QUAD_CurrentVersionRun_dac1 {
  strings:
    $key_dac1 = { 89 ae [2] ad a0 [2] 86 8c [2] a8 ae [2] bc b5 [2] b3 af [2] ad b2 [2] af b3 [2] b4 b5 [2] a8 b2 [2] b4 9d }

  condition:
    any of them
}
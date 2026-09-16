rule TTP_XOR_QUAD_CurrentVersionRun_dac4 {
  strings:
    $key_dac4 = { 89 ab [2] ad a5 [2] 86 89 [2] a8 ab [2] bc b0 [2] b3 aa [2] ad b7 [2] af b6 [2] b4 b0 [2] a8 b7 [2] b4 98 }

  condition:
    any of them
}
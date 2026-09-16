rule TTP_XOR_QUAD_CurrentVersionRun_1dac {
  strings:
    $key_1dac = { 4e c3 [2] 6a cd [2] 41 e1 [2] 6f c3 [2] 7b d8 [2] 74 c2 [2] 6a df [2] 68 de [2] 73 d8 [2] 6f df [2] 73 f0 }

  condition:
    any of them
}
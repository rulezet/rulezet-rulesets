rule TTP_XOR_QUAD_CurrentVersionRun_7dac {
  strings:
    $key_7dac = { 2e c3 [2] 0a cd [2] 21 e1 [2] 0f c3 [2] 1b d8 [2] 14 c2 [2] 0a df [2] 08 de [2] 13 d8 [2] 0f df [2] 13 f0 }

  condition:
    any of them
}
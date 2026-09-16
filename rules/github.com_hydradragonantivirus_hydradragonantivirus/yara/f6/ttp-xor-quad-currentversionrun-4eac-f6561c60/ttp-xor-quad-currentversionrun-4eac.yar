rule TTP_XOR_QUAD_CurrentVersionRun_4eac {
  strings:
    $key_4eac = { 1d c3 [2] 39 cd [2] 12 e1 [2] 3c c3 [2] 28 d8 [2] 27 c2 [2] 39 df [2] 3b de [2] 20 d8 [2] 3c df [2] 20 f0 }

  condition:
    any of them
}
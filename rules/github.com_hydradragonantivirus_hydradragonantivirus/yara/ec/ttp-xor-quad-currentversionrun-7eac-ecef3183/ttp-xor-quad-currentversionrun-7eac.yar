rule TTP_XOR_QUAD_CurrentVersionRun_7eac {
  strings:
    $key_7eac = { 2d c3 [2] 09 cd [2] 22 e1 [2] 0c c3 [2] 18 d8 [2] 17 c2 [2] 09 df [2] 0b de [2] 10 d8 [2] 0c df [2] 10 f0 }

  condition:
    any of them
}
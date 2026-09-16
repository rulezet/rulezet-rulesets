rule TTP_XOR_QUAD_CurrentVersionRun_6fac {
  strings:
    $key_6fac = { 3c c3 [2] 18 cd [2] 33 e1 [2] 1d c3 [2] 09 d8 [2] 06 c2 [2] 18 df [2] 1a de [2] 01 d8 [2] 1d df [2] 01 f0 }

  condition:
    any of them
}
rule TTP_XOR_QUAD_CurrentVersionRun_1fac {
  strings:
    $key_1fac = { 4c c3 [2] 68 cd [2] 43 e1 [2] 6d c3 [2] 79 d8 [2] 76 c2 [2] 68 df [2] 6a de [2] 71 d8 [2] 6d df [2] 71 f0 }

  condition:
    any of them
}
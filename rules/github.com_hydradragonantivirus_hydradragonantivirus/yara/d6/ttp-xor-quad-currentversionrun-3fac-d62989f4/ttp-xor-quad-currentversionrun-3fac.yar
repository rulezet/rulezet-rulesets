rule TTP_XOR_QUAD_CurrentVersionRun_3fac {
  strings:
    $key_3fac = { 6c c3 [2] 48 cd [2] 63 e1 [2] 4d c3 [2] 59 d8 [2] 56 c2 [2] 48 df [2] 4a de [2] 51 d8 [2] 4d df [2] 51 f0 }

  condition:
    any of them
}
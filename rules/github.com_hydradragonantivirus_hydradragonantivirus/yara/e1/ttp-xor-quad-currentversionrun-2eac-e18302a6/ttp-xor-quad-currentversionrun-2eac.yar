rule TTP_XOR_QUAD_CurrentVersionRun_2eac {
  strings:
    $key_2eac = { 7d c3 [2] 59 cd [2] 72 e1 [2] 5c c3 [2] 48 d8 [2] 47 c2 [2] 59 df [2] 5b de [2] 40 d8 [2] 5c df [2] 40 f0 }

  condition:
    any of them
}
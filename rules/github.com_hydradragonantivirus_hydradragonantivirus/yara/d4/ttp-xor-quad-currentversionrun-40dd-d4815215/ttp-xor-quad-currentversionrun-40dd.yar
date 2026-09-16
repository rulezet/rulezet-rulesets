rule TTP_XOR_QUAD_CurrentVersionRun_40dd {
  strings:
    $key_40dd = { 13 b2 [2] 37 bc [2] 1c 90 [2] 32 b2 [2] 26 a9 [2] 29 b3 [2] 37 ae [2] 35 af [2] 2e a9 [2] 32 ae [2] 2e 81 }

  condition:
    any of them
}
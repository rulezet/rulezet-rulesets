rule TTP_XOR_QUAD_CurrentVersionRun_5cac {
  strings:
    $key_5cac = { 0f c3 [2] 2b cd [2] 00 e1 [2] 2e c3 [2] 3a d8 [2] 35 c2 [2] 2b df [2] 29 de [2] 32 d8 [2] 2e df [2] 32 f0 }

  condition:
    any of them
}
rule TTP_XOR_QUAD_CurrentVersionRun_7cac {
  strings:
    $key_7cac = { 2f c3 [2] 0b cd [2] 20 e1 [2] 0e c3 [2] 1a d8 [2] 15 c2 [2] 0b df [2] 09 de [2] 12 d8 [2] 0e df [2] 12 f0 }

  condition:
    any of them
}
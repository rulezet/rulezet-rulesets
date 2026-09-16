rule TTP_XOR_QUAD_CurrentVersionRun_1cac {
  strings:
    $key_1cac = { 4f c3 [2] 6b cd [2] 40 e1 [2] 6e c3 [2] 7a d8 [2] 75 c2 [2] 6b df [2] 69 de [2] 72 d8 [2] 6e df [2] 72 f0 }

  condition:
    any of them
}
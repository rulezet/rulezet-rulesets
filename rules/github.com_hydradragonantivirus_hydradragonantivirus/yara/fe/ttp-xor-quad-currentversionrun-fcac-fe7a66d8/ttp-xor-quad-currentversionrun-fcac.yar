rule TTP_XOR_QUAD_CurrentVersionRun_fcac {
  strings:
    $key_fcac = { af c3 [2] 8b cd [2] a0 e1 [2] 8e c3 [2] 9a d8 [2] 95 c2 [2] 8b df [2] 89 de [2] 92 d8 [2] 8e df [2] 92 f0 }

  condition:
    any of them
}
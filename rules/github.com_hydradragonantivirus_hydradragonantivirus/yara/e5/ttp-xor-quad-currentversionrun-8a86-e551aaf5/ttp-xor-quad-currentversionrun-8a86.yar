rule TTP_XOR_QUAD_CurrentVersionRun_8a86 {
  strings:
    $key_8a86 = { d9 e9 [2] fd e7 [2] d6 cb [2] f8 e9 [2] ec f2 [2] e3 e8 [2] fd f5 [2] ff f4 [2] e4 f2 [2] f8 f5 [2] e4 da }

  condition:
    any of them
}
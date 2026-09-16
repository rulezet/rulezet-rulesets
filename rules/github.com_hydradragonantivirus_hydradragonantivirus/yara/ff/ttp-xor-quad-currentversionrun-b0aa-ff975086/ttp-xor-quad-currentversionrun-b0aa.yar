rule TTP_XOR_QUAD_CurrentVersionRun_b0aa {
  strings:
    $key_b0aa = { e3 c5 [2] c7 cb [2] ec e7 [2] c2 c5 [2] d6 de [2] d9 c4 [2] c7 d9 [2] c5 d8 [2] de de [2] c2 d9 [2] de f6 }

  condition:
    any of them
}
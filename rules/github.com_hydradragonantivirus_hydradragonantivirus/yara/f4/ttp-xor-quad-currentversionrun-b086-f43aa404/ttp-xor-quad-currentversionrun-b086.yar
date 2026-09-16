rule TTP_XOR_QUAD_CurrentVersionRun_b086 {
  strings:
    $key_b086 = { e3 e9 [2] c7 e7 [2] ec cb [2] c2 e9 [2] d6 f2 [2] d9 e8 [2] c7 f5 [2] c5 f4 [2] de f2 [2] c2 f5 [2] de da }

  condition:
    any of them
}
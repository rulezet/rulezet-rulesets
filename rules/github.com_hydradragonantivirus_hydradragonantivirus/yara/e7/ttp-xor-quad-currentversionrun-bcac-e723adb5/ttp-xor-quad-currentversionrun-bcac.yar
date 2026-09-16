rule TTP_XOR_QUAD_CurrentVersionRun_bcac {
  strings:
    $key_bcac = { ef c3 [2] cb cd [2] e0 e1 [2] ce c3 [2] da d8 [2] d5 c2 [2] cb df [2] c9 de [2] d2 d8 [2] ce df [2] d2 f0 }

  condition:
    any of them
}
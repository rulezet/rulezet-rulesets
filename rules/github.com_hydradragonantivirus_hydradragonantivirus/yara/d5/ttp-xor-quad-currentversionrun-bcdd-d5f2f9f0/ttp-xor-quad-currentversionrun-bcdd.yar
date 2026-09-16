rule TTP_XOR_QUAD_CurrentVersionRun_bcdd {
  strings:
    $key_bcdd = { ef b2 [2] cb bc [2] e0 90 [2] ce b2 [2] da a9 [2] d5 b3 [2] cb ae [2] c9 af [2] d2 a9 [2] ce ae [2] d2 81 }

  condition:
    any of them
}
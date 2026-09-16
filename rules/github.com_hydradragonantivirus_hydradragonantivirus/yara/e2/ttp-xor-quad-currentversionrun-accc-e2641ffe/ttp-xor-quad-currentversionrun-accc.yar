rule TTP_XOR_QUAD_CurrentVersionRun_accc {
  strings:
    $key_accc = { ff a3 [2] db ad [2] f0 81 [2] de a3 [2] ca b8 [2] c5 a2 [2] db bf [2] d9 be [2] c2 b8 [2] de bf [2] c2 90 }

  condition:
    any of them
}
rule TTP_XOR_QUAD_CurrentVersionRun_91aa {
  strings:
    $key_91aa = { c2 c5 [2] e6 cb [2] cd e7 [2] e3 c5 [2] f7 de [2] f8 c4 [2] e6 d9 [2] e4 d8 [2] ff de [2] e3 d9 [2] ff f6 }

  condition:
    any of them
}
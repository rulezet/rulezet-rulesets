rule TTP_XOR_QUAD_CurrentVersionRun_acba {
  strings:
    $key_acba = { ff d5 [2] db db [2] f0 f7 [2] de d5 [2] ca ce [2] c5 d4 [2] db c9 [2] d9 c8 [2] c2 ce [2] de c9 [2] c2 e6 }

  condition:
    any of them
}
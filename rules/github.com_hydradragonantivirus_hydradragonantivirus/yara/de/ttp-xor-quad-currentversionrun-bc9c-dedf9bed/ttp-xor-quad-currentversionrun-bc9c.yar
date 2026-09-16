rule TTP_XOR_QUAD_CurrentVersionRun_bc9c {
  strings:
    $key_bc9c = { ef f3 [2] cb fd [2] e0 d1 [2] ce f3 [2] da e8 [2] d5 f2 [2] cb ef [2] c9 ee [2] d2 e8 [2] ce ef [2] d2 c0 }

  condition:
    any of them
}
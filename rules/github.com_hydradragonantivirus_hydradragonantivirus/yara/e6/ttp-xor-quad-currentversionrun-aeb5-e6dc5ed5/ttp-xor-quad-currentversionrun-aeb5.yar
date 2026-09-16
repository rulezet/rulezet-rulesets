rule TTP_XOR_QUAD_CurrentVersionRun_aeb5 {
  strings:
    $key_aeb5 = { fd da [2] d9 d4 [2] f2 f8 [2] dc da [2] c8 c1 [2] c7 db [2] d9 c6 [2] db c7 [2] c0 c1 [2] dc c6 [2] c0 e9 }

  condition:
    any of them
}
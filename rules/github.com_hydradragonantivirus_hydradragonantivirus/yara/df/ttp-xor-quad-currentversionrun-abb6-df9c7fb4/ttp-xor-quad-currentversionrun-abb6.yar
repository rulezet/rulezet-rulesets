rule TTP_XOR_QUAD_CurrentVersionRun_abb6 {
  strings:
    $key_abb6 = { f8 d9 [2] dc d7 [2] f7 fb [2] d9 d9 [2] cd c2 [2] c2 d8 [2] dc c5 [2] de c4 [2] c5 c2 [2] d9 c5 [2] c5 ea }

  condition:
    any of them
}
rule TTP_XOR_QUAD_CurrentVersionRun_bca3 {
  strings:
    $key_bca3 = { ef cc [2] cb c2 [2] e0 ee [2] ce cc [2] da d7 [2] d5 cd [2] cb d0 [2] c9 d1 [2] d2 d7 [2] ce d0 [2] d2 ff }

  condition:
    any of them
}
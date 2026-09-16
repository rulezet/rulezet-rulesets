rule TTP_XOR_QUAD_CurrentVersionRun_aea3 {
  strings:
    $key_aea3 = { fd cc [2] d9 c2 [2] f2 ee [2] dc cc [2] c8 d7 [2] c7 cd [2] d9 d0 [2] db d1 [2] c0 d7 [2] dc d0 [2] c0 ff }

  condition:
    any of them
}
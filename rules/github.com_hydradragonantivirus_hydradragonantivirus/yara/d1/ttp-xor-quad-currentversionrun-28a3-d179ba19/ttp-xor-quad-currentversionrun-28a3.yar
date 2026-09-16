rule TTP_XOR_QUAD_CurrentVersionRun_28a3 {
  strings:
    $key_28a3 = { 7b cc [2] 5f c2 [2] 74 ee [2] 5a cc [2] 4e d7 [2] 41 cd [2] 5f d0 [2] 5d d1 [2] 46 d7 [2] 5a d0 [2] 46 ff }

  condition:
    any of them
}
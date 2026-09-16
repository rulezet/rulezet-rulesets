rule TTP_XOR_QUAD_CurrentVersionRun_39a3 {
  strings:
    $key_39a3 = { 6a cc [2] 4e c2 [2] 65 ee [2] 4b cc [2] 5f d7 [2] 50 cd [2] 4e d0 [2] 4c d1 [2] 57 d7 [2] 4b d0 [2] 57 ff }

  condition:
    any of them
}
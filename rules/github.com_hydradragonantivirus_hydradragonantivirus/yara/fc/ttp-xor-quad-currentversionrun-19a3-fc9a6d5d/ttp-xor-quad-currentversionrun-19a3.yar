rule TTP_XOR_QUAD_CurrentVersionRun_19a3 {
  strings:
    $key_19a3 = { 4a cc [2] 6e c2 [2] 45 ee [2] 6b cc [2] 7f d7 [2] 70 cd [2] 6e d0 [2] 6c d1 [2] 77 d7 [2] 6b d0 [2] 77 ff }

  condition:
    any of them
}
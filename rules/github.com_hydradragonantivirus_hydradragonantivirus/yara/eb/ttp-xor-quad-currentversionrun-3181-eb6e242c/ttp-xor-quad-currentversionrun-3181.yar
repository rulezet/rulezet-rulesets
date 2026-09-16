rule TTP_XOR_QUAD_CurrentVersionRun_3181 {
  strings:
    $key_3181 = { 62 ee [2] 46 e0 [2] 6d cc [2] 43 ee [2] 57 f5 [2] 58 ef [2] 46 f2 [2] 44 f3 [2] 5f f5 [2] 43 f2 [2] 5f dd }

  condition:
    any of them
}
rule TTP_XOR_QUAD_CurrentVersionRun_2181 {
  strings:
    $key_2181 = { 72 ee [2] 56 e0 [2] 7d cc [2] 53 ee [2] 47 f5 [2] 48 ef [2] 56 f2 [2] 54 f3 [2] 4f f5 [2] 53 f2 [2] 4f dd }

  condition:
    any of them
}
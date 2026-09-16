rule TTP_XOR_QUAD_CurrentVersionRun_0181 {
  strings:
    $key_0181 = { 52 ee [2] 76 e0 [2] 5d cc [2] 73 ee [2] 67 f5 [2] 68 ef [2] 76 f2 [2] 74 f3 [2] 6f f5 [2] 73 f2 [2] 6f dd }

  condition:
    any of them
}
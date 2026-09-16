rule TTP_XOR_QUAD_CurrentVersionRun_2180 {
  strings:
    $key_2180 = { 72 ef [2] 56 e1 [2] 7d cd [2] 53 ef [2] 47 f4 [2] 48 ee [2] 56 f3 [2] 54 f2 [2] 4f f4 [2] 53 f3 [2] 4f dc }

  condition:
    any of them
}
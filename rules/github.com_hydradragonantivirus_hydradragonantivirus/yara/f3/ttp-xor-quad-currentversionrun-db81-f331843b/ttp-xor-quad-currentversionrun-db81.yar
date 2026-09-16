rule TTP_XOR_QUAD_CurrentVersionRun_db81 {
  strings:
    $key_db81 = { 88 ee [2] ac e0 [2] 87 cc [2] a9 ee [2] bd f5 [2] b2 ef [2] ac f2 [2] ae f3 [2] b5 f5 [2] a9 f2 [2] b5 dd }

  condition:
    any of them
}
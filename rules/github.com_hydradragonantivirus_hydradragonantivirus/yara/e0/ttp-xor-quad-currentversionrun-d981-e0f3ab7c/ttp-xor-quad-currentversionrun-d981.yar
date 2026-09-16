rule TTP_XOR_QUAD_CurrentVersionRun_d981 {
  strings:
    $key_d981 = { 8a ee [2] ae e0 [2] 85 cc [2] ab ee [2] bf f5 [2] b0 ef [2] ae f2 [2] ac f3 [2] b7 f5 [2] ab f2 [2] b7 dd }

  condition:
    any of them
}
rule TTP_XOR_QUAD_CurrentVersionRun_9380 {
  strings:
    $key_9380 = { c0 ef [2] e4 e1 [2] cf cd [2] e1 ef [2] f5 f4 [2] fa ee [2] e4 f3 [2] e6 f2 [2] fd f4 [2] e1 f3 [2] fd dc }

  condition:
    any of them
}
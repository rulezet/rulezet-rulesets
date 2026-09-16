rule TTP_XOR_QUAD_CurrentVersionRun_c280 {
  strings:
    $key_c280 = { 91 ef [2] b5 e1 [2] 9e cd [2] b0 ef [2] a4 f4 [2] ab ee [2] b5 f3 [2] b7 f2 [2] ac f4 [2] b0 f3 [2] ac dc }

  condition:
    any of them
}
rule TTP_XOR_QUAD_CurrentVersionRun_d79c {
  strings:
    $key_d79c = { 84 f3 [2] a0 fd [2] 8b d1 [2] a5 f3 [2] b1 e8 [2] be f2 [2] a0 ef [2] a2 ee [2] b9 e8 [2] a5 ef [2] b9 c0 }

  condition:
    any of them
}
rule TTP_XOR_QUAD_CurrentVersionRun_cad3 {
  strings:
    $key_cad3 = { 99 bc [2] bd b2 [2] 96 9e [2] b8 bc [2] ac a7 [2] a3 bd [2] bd a0 [2] bf a1 [2] a4 a7 [2] b8 a0 [2] a4 8f }

  condition:
    any of them
}
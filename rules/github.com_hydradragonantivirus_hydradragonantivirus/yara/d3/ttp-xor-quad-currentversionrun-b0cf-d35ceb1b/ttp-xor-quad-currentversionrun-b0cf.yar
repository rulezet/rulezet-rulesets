rule TTP_XOR_QUAD_CurrentVersionRun_b0cf {
  strings:
    $key_b0cf = { e3 a0 [2] c7 ae [2] ec 82 [2] c2 a0 [2] d6 bb [2] d9 a1 [2] c7 bc [2] c5 bd [2] de bb [2] c2 bc [2] de 93 }

  condition:
    any of them
}
rule TTP_XOR_QUAD_CurrentVersionRun_decf {
  strings:
    $key_decf = { 8d a0 [2] a9 ae [2] 82 82 [2] ac a0 [2] b8 bb [2] b7 a1 [2] a9 bc [2] ab bd [2] b0 bb [2] ac bc [2] b0 93 }

  condition:
    any of them
}
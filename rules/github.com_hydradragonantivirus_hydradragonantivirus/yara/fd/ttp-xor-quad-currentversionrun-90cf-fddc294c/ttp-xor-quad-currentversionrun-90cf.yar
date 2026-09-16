rule TTP_XOR_QUAD_CurrentVersionRun_90cf {
  strings:
    $key_90cf = { c3 a0 [2] e7 ae [2] cc 82 [2] e2 a0 [2] f6 bb [2] f9 a1 [2] e7 bc [2] e5 bd [2] fe bb [2] e2 bc [2] fe 93 }

  condition:
    any of them
}
rule TTP_XOR_QUAD_CurrentVersionRun_b5cf {
  strings:
    $key_b5cf = { e6 a0 [2] c2 ae [2] e9 82 [2] c7 a0 [2] d3 bb [2] dc a1 [2] c2 bc [2] c0 bd [2] db bb [2] c7 bc [2] db 93 }

  condition:
    any of them
}
rule TTP_XOR_QUAD_CurrentVersionRun_fda7 {
  strings:
    $key_fda7 = { ae c8 [2] 8a c6 [2] a1 ea [2] 8f c8 [2] 9b d3 [2] 94 c9 [2] 8a d4 [2] 88 d5 [2] 93 d3 [2] 8f d4 [2] 93 fb }

  condition:
    any of them
}
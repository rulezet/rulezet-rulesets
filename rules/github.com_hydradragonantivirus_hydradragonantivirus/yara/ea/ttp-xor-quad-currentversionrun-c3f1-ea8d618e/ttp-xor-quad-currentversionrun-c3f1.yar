rule TTP_XOR_QUAD_CurrentVersionRun_c3f1 {
  strings:
    $key_c3f1 = { 90 9e [2] b4 90 [2] 9f bc [2] b1 9e [2] a5 85 [2] aa 9f [2] b4 82 [2] b6 83 [2] ad 85 [2] b1 82 [2] ad ad }

  condition:
    any of them
}
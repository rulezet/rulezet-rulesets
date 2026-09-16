rule TTP_XOR_QUAD_CurrentVersionRun_d6e0 {
  strings:
    $key_d6e0 = { 85 8f [2] a1 81 [2] 8a ad [2] a4 8f [2] b0 94 [2] bf 8e [2] a1 93 [2] a3 92 [2] b8 94 [2] a4 93 [2] b8 bc }

  condition:
    any of them
}
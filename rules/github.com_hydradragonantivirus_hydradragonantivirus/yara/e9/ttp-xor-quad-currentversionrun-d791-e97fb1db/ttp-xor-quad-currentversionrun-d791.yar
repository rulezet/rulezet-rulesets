rule TTP_XOR_QUAD_CurrentVersionRun_d791 {
  strings:
    $key_d791 = { 84 fe [2] a0 f0 [2] 8b dc [2] a5 fe [2] b1 e5 [2] be ff [2] a0 e2 [2] a2 e3 [2] b9 e5 [2] a5 e2 [2] b9 cd }

  condition:
    any of them
}
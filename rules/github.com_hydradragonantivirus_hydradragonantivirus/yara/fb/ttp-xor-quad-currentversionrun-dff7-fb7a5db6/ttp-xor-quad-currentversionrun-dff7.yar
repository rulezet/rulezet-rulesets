rule TTP_XOR_QUAD_CurrentVersionRun_dff7 {
  strings:
    $key_dff7 = { 8c 98 [2] a8 96 [2] 83 ba [2] ad 98 [2] b9 83 [2] b6 99 [2] a8 84 [2] aa 85 [2] b1 83 [2] ad 84 [2] b1 ab }

  condition:
    any of them
}
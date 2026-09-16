rule TTP_XOR_QUAD_CurrentVersionRun_c4f7 {
  strings:
    $key_c4f7 = { 97 98 [2] b3 96 [2] 98 ba [2] b6 98 [2] a2 83 [2] ad 99 [2] b3 84 [2] b1 85 [2] aa 83 [2] b6 84 [2] aa ab }

  condition:
    any of them
}
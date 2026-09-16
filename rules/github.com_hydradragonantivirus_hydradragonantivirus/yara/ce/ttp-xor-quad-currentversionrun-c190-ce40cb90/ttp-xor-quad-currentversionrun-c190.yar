rule TTP_XOR_QUAD_CurrentVersionRun_c190 {
  strings:
    $key_c190 = { 92 ff [2] b6 f1 [2] 9d dd [2] b3 ff [2] a7 e4 [2] a8 fe [2] b6 e3 [2] b4 e2 [2] af e4 [2] b3 e3 [2] af cc }

  condition:
    any of them
}
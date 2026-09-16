rule TTP_XOR_QUAD_CurrentVersionRun_d990 {
  strings:
    $key_d990 = { 8a ff [2] ae f1 [2] 85 dd [2] ab ff [2] bf e4 [2] b0 fe [2] ae e3 [2] ac e2 [2] b7 e4 [2] ab e3 [2] b7 cc }

  condition:
    any of them
}
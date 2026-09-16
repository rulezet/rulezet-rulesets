rule TTP_XOR_QUAD_CurrentVersionRun_c5b3 {
  strings:
    $key_c5b3 = { 96 dc [2] b2 d2 [2] 99 fe [2] b7 dc [2] a3 c7 [2] ac dd [2] b2 c0 [2] b0 c1 [2] ab c7 [2] b7 c0 [2] ab ef }

  condition:
    any of them
}
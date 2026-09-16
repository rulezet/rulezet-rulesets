rule TTP_XOR_QUAD_CurrentVersionRun_de90 {
  strings:
    $key_de90 = { 8d ff [2] a9 f1 [2] 82 dd [2] ac ff [2] b8 e4 [2] b7 fe [2] a9 e3 [2] ab e2 [2] b0 e4 [2] ac e3 [2] b0 cc }

  condition:
    any of them
}
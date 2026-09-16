rule TTP_XOR_QUAD_CurrentVersionRun_ca90 {
  strings:
    $key_ca90 = { 99 ff [2] bd f1 [2] 96 dd [2] b8 ff [2] ac e4 [2] a3 fe [2] bd e3 [2] bf e2 [2] a4 e4 [2] b8 e3 [2] a4 cc }

  condition:
    any of them
}
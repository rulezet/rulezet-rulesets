rule TTP_XOR_QUAD_CurrentVersionRun_c590 {
  strings:
    $key_c590 = { 96 ff [2] b2 f1 [2] 99 dd [2] b7 ff [2] a3 e4 [2] ac fe [2] b2 e3 [2] b0 e2 [2] ab e4 [2] b7 e3 [2] ab cc }

  condition:
    any of them
}
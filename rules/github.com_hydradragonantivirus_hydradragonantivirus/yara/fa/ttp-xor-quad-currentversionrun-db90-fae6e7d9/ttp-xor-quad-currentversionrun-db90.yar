rule TTP_XOR_QUAD_CurrentVersionRun_db90 {
  strings:
    $key_db90 = { 88 ff [2] ac f1 [2] 87 dd [2] a9 ff [2] bd e4 [2] b2 fe [2] ac e3 [2] ae e2 [2] b5 e4 [2] a9 e3 [2] b5 cc }

  condition:
    any of them
}
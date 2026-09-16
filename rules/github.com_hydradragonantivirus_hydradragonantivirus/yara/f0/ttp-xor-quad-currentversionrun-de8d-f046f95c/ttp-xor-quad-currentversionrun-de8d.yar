rule TTP_XOR_QUAD_CurrentVersionRun_de8d {
  strings:
    $key_de8d = { 8d e2 [2] a9 ec [2] 82 c0 [2] ac e2 [2] b8 f9 [2] b7 e3 [2] a9 fe [2] ab ff [2] b0 f9 [2] ac fe [2] b0 d1 }

  condition:
    any of them
}
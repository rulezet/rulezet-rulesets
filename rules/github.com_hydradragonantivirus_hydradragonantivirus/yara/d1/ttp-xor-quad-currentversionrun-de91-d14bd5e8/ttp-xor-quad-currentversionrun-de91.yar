rule TTP_XOR_QUAD_CurrentVersionRun_de91 {
  strings:
    $key_de91 = { 8d fe [2] a9 f0 [2] 82 dc [2] ac fe [2] b8 e5 [2] b7 ff [2] a9 e2 [2] ab e3 [2] b0 e5 [2] ac e2 [2] b0 cd }

  condition:
    any of them
}
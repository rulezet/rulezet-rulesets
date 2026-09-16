rule TTP_XOR_QUAD_CurrentVersionRun_db91 {
  strings:
    $key_db91 = { 88 fe [2] ac f0 [2] 87 dc [2] a9 fe [2] bd e5 [2] b2 ff [2] ac e2 [2] ae e3 [2] b5 e5 [2] a9 e2 [2] b5 cd }

  condition:
    any of them
}
rule TTP_XOR_QUAD_CurrentVersionRun_cd91 {
  strings:
    $key_cd91 = { 9e fe [2] ba f0 [2] 91 dc [2] bf fe [2] ab e5 [2] a4 ff [2] ba e2 [2] b8 e3 [2] a3 e5 [2] bf e2 [2] a3 cd }

  condition:
    any of them
}
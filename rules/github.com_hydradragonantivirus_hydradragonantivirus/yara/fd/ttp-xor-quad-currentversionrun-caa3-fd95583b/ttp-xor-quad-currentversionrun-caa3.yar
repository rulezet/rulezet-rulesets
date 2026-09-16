rule TTP_XOR_QUAD_CurrentVersionRun_caa3 {
  strings:
    $key_caa3 = { 99 cc [2] bd c2 [2] 96 ee [2] b8 cc [2] ac d7 [2] a3 cd [2] bd d0 [2] bf d1 [2] a4 d7 [2] b8 d0 [2] a4 ff }

  condition:
    any of them
}
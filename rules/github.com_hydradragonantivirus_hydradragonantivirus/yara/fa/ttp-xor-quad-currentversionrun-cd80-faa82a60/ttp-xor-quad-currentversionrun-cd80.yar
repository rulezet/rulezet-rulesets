rule TTP_XOR_QUAD_CurrentVersionRun_cd80 {
  strings:
    $key_cd80 = { 9e ef [2] ba e1 [2] 91 cd [2] bf ef [2] ab f4 [2] a4 ee [2] ba f3 [2] b8 f2 [2] a3 f4 [2] bf f3 [2] a3 dc }

  condition:
    any of them
}
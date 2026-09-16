rule TTP_XOR_QUAD_CurrentVersionRun_c2db {
  strings:
    $key_c2db = { 91 b4 [2] b5 ba [2] 9e 96 [2] b0 b4 [2] a4 af [2] ab b5 [2] b5 a8 [2] b7 a9 [2] ac af [2] b0 a8 [2] ac 87 }

  condition:
    any of them
}
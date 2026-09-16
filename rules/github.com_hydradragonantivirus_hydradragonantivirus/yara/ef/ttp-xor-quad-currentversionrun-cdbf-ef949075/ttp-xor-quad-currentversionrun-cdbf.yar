rule TTP_XOR_QUAD_CurrentVersionRun_cdbf {
  strings:
    $key_cdbf = { 9e d0 [2] ba de [2] 91 f2 [2] bf d0 [2] ab cb [2] a4 d1 [2] ba cc [2] b8 cd [2] a3 cb [2] bf cc [2] a3 e3 }

  condition:
    any of them
}
rule TTP_XOR_QUAD_CurrentVersionRun_cfbf {
  strings:
    $key_cfbf = { 9c d0 [2] b8 de [2] 93 f2 [2] bd d0 [2] a9 cb [2] a6 d1 [2] b8 cc [2] ba cd [2] a1 cb [2] bd cc [2] a1 e3 }

  condition:
    any of them
}
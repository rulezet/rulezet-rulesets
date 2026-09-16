rule TTP_XOR_QUAD_CurrentVersionRun_c6bf {
  strings:
    $key_c6bf = { 95 d0 [2] b1 de [2] 9a f2 [2] b4 d0 [2] a0 cb [2] af d1 [2] b1 cc [2] b3 cd [2] a8 cb [2] b4 cc [2] a8 e3 }

  condition:
    any of them
}
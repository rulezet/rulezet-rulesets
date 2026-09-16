rule TTP_XOR_QUAD_CurrentVersionRun_0ebf {
  strings:
    $key_0ebf = { 5d d0 [2] 79 de [2] 52 f2 [2] 7c d0 [2] 68 cb [2] 67 d1 [2] 79 cc [2] 7b cd [2] 60 cb [2] 7c cc [2] 60 e3 }

  condition:
    any of them
}
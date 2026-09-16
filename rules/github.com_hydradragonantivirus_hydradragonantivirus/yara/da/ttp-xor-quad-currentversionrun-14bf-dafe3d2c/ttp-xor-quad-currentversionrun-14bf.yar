rule TTP_XOR_QUAD_CurrentVersionRun_14bf {
  strings:
    $key_14bf = { 47 d0 [2] 63 de [2] 48 f2 [2] 66 d0 [2] 72 cb [2] 7d d1 [2] 63 cc [2] 61 cd [2] 7a cb [2] 66 cc [2] 7a e3 }

  condition:
    any of them
}
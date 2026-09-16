rule TTP_XOR_QUAD_CurrentVersionRun_4fbf {
  strings:
    $key_4fbf = { 1c d0 [2] 38 de [2] 13 f2 [2] 3d d0 [2] 29 cb [2] 26 d1 [2] 38 cc [2] 3a cd [2] 21 cb [2] 3d cc [2] 21 e3 }

  condition:
    any of them
}
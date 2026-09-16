rule TTP_XOR_QUAD_CurrentVersionRun_3fbf {
  strings:
    $key_3fbf = { 6c d0 [2] 48 de [2] 63 f2 [2] 4d d0 [2] 59 cb [2] 56 d1 [2] 48 cc [2] 4a cd [2] 51 cb [2] 4d cc [2] 51 e3 }

  condition:
    any of them
}
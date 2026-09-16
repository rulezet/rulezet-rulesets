rule TTP_XOR_QUAD_CurrentVersionRun_7fbf {
  strings:
    $key_7fbf = { 2c d0 [2] 08 de [2] 23 f2 [2] 0d d0 [2] 19 cb [2] 16 d1 [2] 08 cc [2] 0a cd [2] 11 cb [2] 0d cc [2] 11 e3 }

  condition:
    any of them
}
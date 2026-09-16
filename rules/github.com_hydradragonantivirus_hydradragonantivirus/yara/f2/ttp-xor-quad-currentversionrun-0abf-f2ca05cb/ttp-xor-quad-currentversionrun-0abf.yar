rule TTP_XOR_QUAD_CurrentVersionRun_0abf {
  strings:
    $key_0abf = { 59 d0 [2] 7d de [2] 56 f2 [2] 78 d0 [2] 6c cb [2] 63 d1 [2] 7d cc [2] 7f cd [2] 64 cb [2] 78 cc [2] 64 e3 }

  condition:
    any of them
}
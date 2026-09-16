rule TTP_XOR_QUAD_CurrentVersionRun_7abf {
  strings:
    $key_7abf = { 29 d0 [2] 0d de [2] 26 f2 [2] 08 d0 [2] 1c cb [2] 13 d1 [2] 0d cc [2] 0f cd [2] 14 cb [2] 08 cc [2] 14 e3 }

  condition:
    any of them
}
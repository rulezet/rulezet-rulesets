rule TTP_XOR_QUAD_CurrentVersionRun_7dbf {
  strings:
    $key_7dbf = { 2e d0 [2] 0a de [2] 21 f2 [2] 0f d0 [2] 1b cb [2] 14 d1 [2] 0a cc [2] 08 cd [2] 13 cb [2] 0f cc [2] 13 e3 }

  condition:
    any of them
}
rule TTP_XOR_QUAD_CurrentVersionRun_a99d {
  strings:
    $key_a99d = { fa f2 [2] de fc [2] f5 d0 [2] db f2 [2] cf e9 [2] c0 f3 [2] de ee [2] dc ef [2] c7 e9 [2] db ee [2] c7 c1 }

  condition:
    any of them
}
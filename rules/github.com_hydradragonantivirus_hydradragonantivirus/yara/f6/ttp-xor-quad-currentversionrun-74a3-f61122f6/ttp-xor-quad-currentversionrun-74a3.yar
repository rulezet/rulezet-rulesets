rule TTP_XOR_QUAD_CurrentVersionRun_74a3 {
  strings:
    $key_74a3 = { 27 cc [2] 03 c2 [2] 28 ee [2] 06 cc [2] 12 d7 [2] 1d cd [2] 03 d0 [2] 01 d1 [2] 1a d7 [2] 06 d0 [2] 1a ff }

  condition:
    any of them
}
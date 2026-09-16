rule TTP_XOR_QUAD_CurrentVersionRun_33a3 {
  strings:
    $key_33a3 = { 60 cc [2] 44 c2 [2] 6f ee [2] 41 cc [2] 55 d7 [2] 5a cd [2] 44 d0 [2] 46 d1 [2] 5d d7 [2] 41 d0 [2] 5d ff }

  condition:
    any of them
}
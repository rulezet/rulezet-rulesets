rule TTP_XOR_QUAD_CurrentVersionRun_23a3 {
  strings:
    $key_23a3 = { 70 cc [2] 54 c2 [2] 7f ee [2] 51 cc [2] 45 d7 [2] 4a cd [2] 54 d0 [2] 56 d1 [2] 4d d7 [2] 51 d0 [2] 4d ff }

  condition:
    any of them
}
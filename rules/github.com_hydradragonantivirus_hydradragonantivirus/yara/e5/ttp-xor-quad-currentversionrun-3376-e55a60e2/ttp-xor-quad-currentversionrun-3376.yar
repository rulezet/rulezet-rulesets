rule TTP_XOR_QUAD_CurrentVersionRun_3376 {
  strings:
    $key_3376 = { 60 19 [2] 44 17 [2] 6f 3b [2] 41 19 [2] 55 02 [2] 5a 18 [2] 44 05 [2] 46 04 [2] 5d 02 [2] 41 05 [2] 5d 2a }

  condition:
    any of them
}
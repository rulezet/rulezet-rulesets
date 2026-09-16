rule TTP_XOR_QUAD_CurrentVersionRun_3356 {
  strings:
    $key_3356 = { 60 39 [2] 44 37 [2] 6f 1b [2] 41 39 [2] 55 22 [2] 5a 38 [2] 44 25 [2] 46 24 [2] 5d 22 [2] 41 25 [2] 5d 0a }

  condition:
    any of them
}
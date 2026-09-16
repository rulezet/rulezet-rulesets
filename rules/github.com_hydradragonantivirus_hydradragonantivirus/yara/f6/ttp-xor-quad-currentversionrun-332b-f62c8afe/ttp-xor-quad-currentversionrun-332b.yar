rule TTP_XOR_QUAD_CurrentVersionRun_332b {
  strings:
    $key_332b = { 60 44 [2] 44 4a [2] 6f 66 [2] 41 44 [2] 55 5f [2] 5a 45 [2] 44 58 [2] 46 59 [2] 5d 5f [2] 41 58 [2] 5d 77 }

  condition:
    any of them
}
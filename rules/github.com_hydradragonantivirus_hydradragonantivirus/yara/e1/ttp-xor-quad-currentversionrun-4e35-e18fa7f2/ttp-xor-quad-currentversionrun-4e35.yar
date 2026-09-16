rule TTP_XOR_QUAD_CurrentVersionRun_4e35 {
  strings:
    $key_4e35 = { 1d 5a [2] 39 54 [2] 12 78 [2] 3c 5a [2] 28 41 [2] 27 5b [2] 39 46 [2] 3b 47 [2] 20 41 [2] 3c 46 [2] 20 69 }

  condition:
    any of them
}
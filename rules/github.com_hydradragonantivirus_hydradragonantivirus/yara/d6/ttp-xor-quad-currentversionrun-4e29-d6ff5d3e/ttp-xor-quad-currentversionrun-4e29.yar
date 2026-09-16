rule TTP_XOR_QUAD_CurrentVersionRun_4e29 {
  strings:
    $key_4e29 = { 1d 46 [2] 39 48 [2] 12 64 [2] 3c 46 [2] 28 5d [2] 27 47 [2] 39 5a [2] 3b 5b [2] 20 5d [2] 3c 5a [2] 20 75 }

  condition:
    any of them
}
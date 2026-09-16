rule TTP_XOR_QUAD_CurrentVersionRun_5a29 {
  strings:
    $key_5a29 = { 09 46 [2] 2d 48 [2] 06 64 [2] 28 46 [2] 3c 5d [2] 33 47 [2] 2d 5a [2] 2f 5b [2] 34 5d [2] 28 5a [2] 34 75 }

  condition:
    any of them
}
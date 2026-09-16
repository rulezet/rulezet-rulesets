rule TTP_XOR_QUAD_CurrentVersionRun_5a34 {
  strings:
    $key_5a34 = { 09 5b [2] 2d 55 [2] 06 79 [2] 28 5b [2] 3c 40 [2] 33 5a [2] 2d 47 [2] 2f 46 [2] 34 40 [2] 28 47 [2] 34 68 }

  condition:
    any of them
}
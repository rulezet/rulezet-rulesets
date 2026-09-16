rule TTP_XOR_QUAD_CurrentVersionRun_4b19 {
  strings:
    $key_4b19 = { 18 76 [2] 3c 78 [2] 17 54 [2] 39 76 [2] 2d 6d [2] 22 77 [2] 3c 6a [2] 3e 6b [2] 25 6d [2] 39 6a [2] 25 45 }

  condition:
    any of them
}
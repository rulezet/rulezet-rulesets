rule TTP_XOR_QUAD_CurrentVersionRun_4b09 {
  strings:
    $key_4b09 = { 18 66 [2] 3c 68 [2] 17 44 [2] 39 66 [2] 2d 7d [2] 22 67 [2] 3c 7a [2] 3e 7b [2] 25 7d [2] 39 7a [2] 25 55 }

  condition:
    any of them
}
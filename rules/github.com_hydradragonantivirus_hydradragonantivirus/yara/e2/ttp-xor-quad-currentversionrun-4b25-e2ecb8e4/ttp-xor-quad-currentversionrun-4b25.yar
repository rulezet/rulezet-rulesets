rule TTP_XOR_QUAD_CurrentVersionRun_4b25 {
  strings:
    $key_4b25 = { 18 4a [2] 3c 44 [2] 17 68 [2] 39 4a [2] 2d 51 [2] 22 4b [2] 3c 56 [2] 3e 57 [2] 25 51 [2] 39 56 [2] 25 79 }

  condition:
    any of them
}
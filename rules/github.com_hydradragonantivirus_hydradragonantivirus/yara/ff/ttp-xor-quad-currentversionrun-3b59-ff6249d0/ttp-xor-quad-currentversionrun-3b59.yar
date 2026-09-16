rule TTP_XOR_QUAD_CurrentVersionRun_3b59 {
  strings:
    $key_3b59 = { 68 36 [2] 4c 38 [2] 67 14 [2] 49 36 [2] 5d 2d [2] 52 37 [2] 4c 2a [2] 4e 2b [2] 55 2d [2] 49 2a [2] 55 05 }

  condition:
    any of them
}
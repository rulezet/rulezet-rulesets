rule TTP_XOR_QUAD_CurrentVersionRun_1e59 {
  strings:
    $key_1e59 = { 4d 36 [2] 69 38 [2] 42 14 [2] 6c 36 [2] 78 2d [2] 77 37 [2] 69 2a [2] 6b 2b [2] 70 2d [2] 6c 2a [2] 70 05 }

  condition:
    any of them
}
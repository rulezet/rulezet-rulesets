rule TTP_XOR_QUAD_CurrentVersionRun_0e59 {
  strings:
    $key_0e59 = { 5d 36 [2] 79 38 [2] 52 14 [2] 7c 36 [2] 68 2d [2] 67 37 [2] 79 2a [2] 7b 2b [2] 60 2d [2] 7c 2a [2] 60 05 }

  condition:
    any of them
}
rule TTP_XOR_QUAD_CurrentVersionRun_5f14 {
  strings:
    $key_5f14 = { 0c 7b [2] 28 75 [2] 03 59 [2] 2d 7b [2] 39 60 [2] 36 7a [2] 28 67 [2] 2a 66 [2] 31 60 [2] 2d 67 [2] 31 48 }

  condition:
    any of them
}
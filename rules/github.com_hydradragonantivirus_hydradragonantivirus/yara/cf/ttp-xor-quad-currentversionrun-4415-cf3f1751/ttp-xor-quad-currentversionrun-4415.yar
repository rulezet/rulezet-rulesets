rule TTP_XOR_QUAD_CurrentVersionRun_4415 {
  strings:
    $key_4415 = { 17 7a [2] 33 74 [2] 18 58 [2] 36 7a [2] 22 61 [2] 2d 7b [2] 33 66 [2] 31 67 [2] 2a 61 [2] 36 66 [2] 2a 49 }

  condition:
    any of them
}
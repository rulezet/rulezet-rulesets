rule TTP_XOR_QUAD_CurrentVersionRun_4f45 {
  strings:
    $key_4f45 = { 1c 2a [2] 38 24 [2] 13 08 [2] 3d 2a [2] 29 31 [2] 26 2b [2] 38 36 [2] 3a 37 [2] 21 31 [2] 3d 36 [2] 21 19 }

  condition:
    any of them
}
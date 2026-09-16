rule TTP_XOR_QUAD_CurrentVersionRun_6e44 {
  strings:
    $key_6e44 = { 3d 2b [2] 19 25 [2] 32 09 [2] 1c 2b [2] 08 30 [2] 07 2a [2] 19 37 [2] 1b 36 [2] 00 30 [2] 1c 37 [2] 00 18 }

  condition:
    any of them
}
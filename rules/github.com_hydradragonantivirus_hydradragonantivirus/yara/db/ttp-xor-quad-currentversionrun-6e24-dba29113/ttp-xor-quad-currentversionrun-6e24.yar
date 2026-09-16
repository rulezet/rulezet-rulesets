rule TTP_XOR_QUAD_CurrentVersionRun_6e24 {
  strings:
    $key_6e24 = { 3d 4b [2] 19 45 [2] 32 69 [2] 1c 4b [2] 08 50 [2] 07 4a [2] 19 57 [2] 1b 56 [2] 00 50 [2] 1c 57 [2] 00 78 }

  condition:
    any of them
}
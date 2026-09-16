rule TTP_XOR_QUAD_CurrentVersionRun_6e38 {
  strings:
    $key_6e38 = { 3d 57 [2] 19 59 [2] 32 75 [2] 1c 57 [2] 08 4c [2] 07 56 [2] 19 4b [2] 1b 4a [2] 00 4c [2] 1c 4b [2] 00 64 }

  condition:
    any of them
}
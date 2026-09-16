rule TTP_XOR_QUAD_CurrentVersionRun_6e78 {
  strings:
    $key_6e78 = { 3d 17 [2] 19 19 [2] 32 35 [2] 1c 17 [2] 08 0c [2] 07 16 [2] 19 0b [2] 1b 0a [2] 00 0c [2] 1c 0b [2] 00 24 }

  condition:
    any of them
}
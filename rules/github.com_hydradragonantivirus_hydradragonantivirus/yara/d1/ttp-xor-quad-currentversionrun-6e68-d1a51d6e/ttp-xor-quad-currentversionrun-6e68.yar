rule TTP_XOR_QUAD_CurrentVersionRun_6e68 {
  strings:
    $key_6e68 = { 3d 07 [2] 19 09 [2] 32 25 [2] 1c 07 [2] 08 1c [2] 07 06 [2] 19 1b [2] 1b 1a [2] 00 1c [2] 1c 1b [2] 00 34 }

  condition:
    any of them
}
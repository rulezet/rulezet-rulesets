rule TTP_XOR_QUAD_CurrentVersionRun_6ee4 {
  strings:
    $key_6ee4 = { 3d 8b [2] 19 85 [2] 32 a9 [2] 1c 8b [2] 08 90 [2] 07 8a [2] 19 97 [2] 1b 96 [2] 00 90 [2] 1c 97 [2] 00 b8 }

  condition:
    any of them
}
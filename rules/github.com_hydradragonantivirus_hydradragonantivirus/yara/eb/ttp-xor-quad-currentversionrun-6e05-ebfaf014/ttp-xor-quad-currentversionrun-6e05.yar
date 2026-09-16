rule TTP_XOR_QUAD_CurrentVersionRun_6e05 {
  strings:
    $key_6e05 = { 3d 6a [2] 19 64 [2] 32 48 [2] 1c 6a [2] 08 71 [2] 07 6b [2] 19 76 [2] 1b 77 [2] 00 71 [2] 1c 76 [2] 00 59 }

  condition:
    any of them
}
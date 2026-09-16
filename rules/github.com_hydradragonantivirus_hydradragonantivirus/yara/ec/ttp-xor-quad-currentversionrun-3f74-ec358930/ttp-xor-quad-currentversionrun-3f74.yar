rule TTP_XOR_QUAD_CurrentVersionRun_3f74 {
  strings:
    $key_3f74 = { 6c 1b [2] 48 15 [2] 63 39 [2] 4d 1b [2] 59 00 [2] 56 1a [2] 48 07 [2] 4a 06 [2] 51 00 [2] 4d 07 [2] 51 28 }

  condition:
    any of them
}
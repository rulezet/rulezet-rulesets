rule TTP_XOR_QUAD_CurrentVersionRun_7172 {
  strings:
    $key_7172 = { 22 1d [2] 06 13 [2] 2d 3f [2] 03 1d [2] 17 06 [2] 18 1c [2] 06 01 [2] 04 00 [2] 1f 06 [2] 03 01 [2] 1f 2e }

  condition:
    any of them
}
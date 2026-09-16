rule TTP_XOR_QUAD_CurrentVersionRun_6172 {
  strings:
    $key_6172 = { 32 1d [2] 16 13 [2] 3d 3f [2] 13 1d [2] 07 06 [2] 08 1c [2] 16 01 [2] 14 00 [2] 0f 06 [2] 13 01 [2] 0f 2e }

  condition:
    any of them
}
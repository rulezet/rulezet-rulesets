rule TTP_XOR_QUAD_CurrentVersionRun_6e2b {
  strings:
    $key_6e2b = { 3d 44 [2] 19 4a [2] 32 66 [2] 1c 44 [2] 08 5f [2] 07 45 [2] 19 58 [2] 1b 59 [2] 00 5f [2] 1c 58 [2] 00 77 }

  condition:
    any of them
}
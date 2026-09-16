rule TTP_XOR_QUAD_CurrentVersionRun_6e03 {
  strings:
    $key_6e03 = { 3d 6c [2] 19 62 [2] 32 4e [2] 1c 6c [2] 08 77 [2] 07 6d [2] 19 70 [2] 1b 71 [2] 00 77 [2] 1c 70 [2] 00 5f }

  condition:
    any of them
}
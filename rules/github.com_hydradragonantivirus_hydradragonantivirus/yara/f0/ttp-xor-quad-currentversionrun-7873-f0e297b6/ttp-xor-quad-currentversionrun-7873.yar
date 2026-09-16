rule TTP_XOR_QUAD_CurrentVersionRun_7873 {
  strings:
    $key_7873 = { 2b 1c [2] 0f 12 [2] 24 3e [2] 0a 1c [2] 1e 07 [2] 11 1d [2] 0f 00 [2] 0d 01 [2] 16 07 [2] 0a 00 [2] 16 2f }

  condition:
    any of them
}
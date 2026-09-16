rule TTP_XOR_QUAD_CurrentVersionRun_7861 {
  strings:
    $key_7861 = { 2b 0e [2] 0f 00 [2] 24 2c [2] 0a 0e [2] 1e 15 [2] 11 0f [2] 0f 12 [2] 0d 13 [2] 16 15 [2] 0a 12 [2] 16 3d }

  condition:
    any of them
}
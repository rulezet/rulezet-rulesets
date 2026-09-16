rule TTP_XOR_QUAD_CurrentVersionRun_0a61 {
  strings:
    $key_0a61 = { 59 0e [2] 7d 00 [2] 56 2c [2] 78 0e [2] 6c 15 [2] 63 0f [2] 7d 12 [2] 7f 13 [2] 64 15 [2] 78 12 [2] 64 3d }

  condition:
    any of them
}
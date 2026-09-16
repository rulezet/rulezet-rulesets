rule TTP_XOR_QUAD_CurrentVersionRun_7f71 {
  strings:
    $key_7f71 = { 2c 1e [2] 08 10 [2] 23 3c [2] 0d 1e [2] 19 05 [2] 16 1f [2] 08 02 [2] 0a 03 [2] 11 05 [2] 0d 02 [2] 11 2d }

  condition:
    any of them
}
rule TTP_XOR_QUAD_CurrentVersionRun_5f71 {
  strings:
    $key_5f71 = { 0c 1e [2] 28 10 [2] 03 3c [2] 2d 1e [2] 39 05 [2] 36 1f [2] 28 02 [2] 2a 03 [2] 31 05 [2] 2d 02 [2] 31 2d }

  condition:
    any of them
}
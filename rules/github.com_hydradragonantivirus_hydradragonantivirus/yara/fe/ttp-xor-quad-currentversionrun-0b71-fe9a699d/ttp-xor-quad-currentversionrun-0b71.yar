rule TTP_XOR_QUAD_CurrentVersionRun_0b71 {
  strings:
    $key_0b71 = { 58 1e [2] 7c 10 [2] 57 3c [2] 79 1e [2] 6d 05 [2] 62 1f [2] 7c 02 [2] 7e 03 [2] 65 05 [2] 79 02 [2] 65 2d }

  condition:
    any of them
}
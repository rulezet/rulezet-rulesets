rule TTP_XOR_QUAD_CurrentVersionRun_4b0b {
  strings:
    $key_4b0b = { 18 64 [2] 3c 6a [2] 17 46 [2] 39 64 [2] 2d 7f [2] 22 65 [2] 3c 78 [2] 3e 79 [2] 25 7f [2] 39 78 [2] 25 57 }

  condition:
    any of them
}
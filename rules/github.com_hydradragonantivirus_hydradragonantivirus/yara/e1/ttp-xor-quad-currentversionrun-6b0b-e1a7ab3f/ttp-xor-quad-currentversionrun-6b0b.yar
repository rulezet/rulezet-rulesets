rule TTP_XOR_QUAD_CurrentVersionRun_6b0b {
  strings:
    $key_6b0b = { 38 64 [2] 1c 6a [2] 37 46 [2] 19 64 [2] 0d 7f [2] 02 65 [2] 1c 78 [2] 1e 79 [2] 05 7f [2] 19 78 [2] 05 57 }

  condition:
    any of them
}
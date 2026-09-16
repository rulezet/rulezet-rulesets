rule TTP_XOR_QUAD_CurrentVersionRun_1c0b {
  strings:
    $key_1c0b = { 4f 64 [2] 6b 6a [2] 40 46 [2] 6e 64 [2] 7a 7f [2] 75 65 [2] 6b 78 [2] 69 79 [2] 72 7f [2] 6e 78 [2] 72 57 }

  condition:
    any of them
}
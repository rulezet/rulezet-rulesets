rule TTP_XOR_QUAD_CurrentVersionRun_6d17 {
  strings:
    $key_6d17 = { 3e 78 [2] 1a 76 [2] 31 5a [2] 1f 78 [2] 0b 63 [2] 04 79 [2] 1a 64 [2] 18 65 [2] 03 63 [2] 1f 64 [2] 03 4b }

  condition:
    any of them
}
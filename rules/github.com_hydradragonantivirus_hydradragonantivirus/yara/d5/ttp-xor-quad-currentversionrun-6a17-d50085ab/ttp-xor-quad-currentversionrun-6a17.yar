rule TTP_XOR_QUAD_CurrentVersionRun_6a17 {
  strings:
    $key_6a17 = { 39 78 [2] 1d 76 [2] 36 5a [2] 18 78 [2] 0c 63 [2] 03 79 [2] 1d 64 [2] 1f 65 [2] 04 63 [2] 18 64 [2] 04 4b }

  condition:
    any of them
}
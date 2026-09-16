rule TTP_XOR_QUAD_CurrentVersionRun_1617 {
  strings:
    $key_1617 = { 45 78 [2] 61 76 [2] 4a 5a [2] 64 78 [2] 70 63 [2] 7f 79 [2] 61 64 [2] 63 65 [2] 78 63 [2] 64 64 [2] 78 4b }

  condition:
    any of them
}
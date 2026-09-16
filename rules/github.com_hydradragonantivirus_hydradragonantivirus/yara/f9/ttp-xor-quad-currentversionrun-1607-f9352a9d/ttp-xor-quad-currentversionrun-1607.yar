rule TTP_XOR_QUAD_CurrentVersionRun_1607 {
  strings:
    $key_1607 = { 45 68 [2] 61 66 [2] 4a 4a [2] 64 68 [2] 70 73 [2] 7f 69 [2] 61 74 [2] 63 75 [2] 78 73 [2] 64 74 [2] 78 5b }

  condition:
    any of them
}
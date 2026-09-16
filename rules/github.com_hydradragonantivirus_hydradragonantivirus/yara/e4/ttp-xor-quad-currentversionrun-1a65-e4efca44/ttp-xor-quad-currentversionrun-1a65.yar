rule TTP_XOR_QUAD_CurrentVersionRun_1a65 {
  strings:
    $key_1a65 = { 49 0a [2] 6d 04 [2] 46 28 [2] 68 0a [2] 7c 11 [2] 73 0b [2] 6d 16 [2] 6f 17 [2] 74 11 [2] 68 16 [2] 74 39 }

  condition:
    any of them
}
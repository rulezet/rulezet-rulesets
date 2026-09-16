rule TTP_XOR_QUAD_CurrentVersionRun_1a24 {
  strings:
    $key_1a24 = { 49 4b [2] 6d 45 [2] 46 69 [2] 68 4b [2] 7c 50 [2] 73 4a [2] 6d 57 [2] 6f 56 [2] 74 50 [2] 68 57 [2] 74 78 }

  condition:
    any of them
}
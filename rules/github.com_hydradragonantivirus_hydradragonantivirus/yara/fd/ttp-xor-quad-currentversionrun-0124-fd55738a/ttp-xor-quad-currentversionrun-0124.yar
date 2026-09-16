rule TTP_XOR_QUAD_CurrentVersionRun_0124 {
  strings:
    $key_0124 = { 52 4b [2] 76 45 [2] 5d 69 [2] 73 4b [2] 67 50 [2] 68 4a [2] 76 57 [2] 74 56 [2] 6f 50 [2] 73 57 [2] 6f 78 }

  condition:
    any of them
}
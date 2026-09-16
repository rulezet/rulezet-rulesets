rule TTP_XOR_QUAD_CurrentVersionRun_1307 {
  strings:
    $key_1307 = { 40 68 [2] 64 66 [2] 4f 4a [2] 61 68 [2] 75 73 [2] 7a 69 [2] 64 74 [2] 66 75 [2] 7d 73 [2] 61 74 [2] 7d 5b }

  condition:
    any of them
}
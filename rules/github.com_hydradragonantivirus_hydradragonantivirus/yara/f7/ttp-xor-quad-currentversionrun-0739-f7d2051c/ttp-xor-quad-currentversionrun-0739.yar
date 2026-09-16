rule TTP_XOR_QUAD_CurrentVersionRun_0739 {
  strings:
    $key_0739 = { 54 56 [2] 70 58 [2] 5b 74 [2] 75 56 [2] 61 4d [2] 6e 57 [2] 70 4a [2] 72 4b [2] 69 4d [2] 75 4a [2] 69 65 }

  condition:
    any of them
}
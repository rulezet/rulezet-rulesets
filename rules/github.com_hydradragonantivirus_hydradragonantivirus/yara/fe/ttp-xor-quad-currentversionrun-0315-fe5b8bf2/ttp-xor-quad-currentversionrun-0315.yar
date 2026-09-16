rule TTP_XOR_QUAD_CurrentVersionRun_0315 {
  strings:
    $key_0315 = { 50 7a [2] 74 74 [2] 5f 58 [2] 71 7a [2] 65 61 [2] 6a 7b [2] 74 66 [2] 76 67 [2] 6d 61 [2] 71 66 [2] 6d 49 }

  condition:
    any of them
}
rule TTP_XOR_QUAD_CurrentVersionRun_0309 {
  strings:
    $key_0309 = { 50 66 [2] 74 68 [2] 5f 44 [2] 71 66 [2] 65 7d [2] 6a 67 [2] 74 7a [2] 76 7b [2] 6d 7d [2] 71 7a [2] 6d 55 }

  condition:
    any of them
}
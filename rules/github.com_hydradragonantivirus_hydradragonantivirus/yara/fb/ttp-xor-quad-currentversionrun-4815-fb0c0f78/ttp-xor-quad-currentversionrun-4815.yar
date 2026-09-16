rule TTP_XOR_QUAD_CurrentVersionRun_4815 {
  strings:
    $key_4815 = { 1b 7a [2] 3f 74 [2] 14 58 [2] 3a 7a [2] 2e 61 [2] 21 7b [2] 3f 66 [2] 3d 67 [2] 26 61 [2] 3a 66 [2] 26 49 }

  condition:
    any of them
}
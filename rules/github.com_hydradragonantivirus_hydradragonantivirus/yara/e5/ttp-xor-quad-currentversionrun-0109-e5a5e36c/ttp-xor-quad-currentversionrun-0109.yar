rule TTP_XOR_QUAD_CurrentVersionRun_0109 {
  strings:
    $key_0109 = { 52 66 [2] 76 68 [2] 5d 44 [2] 73 66 [2] 67 7d [2] 68 67 [2] 76 7a [2] 74 7b [2] 6f 7d [2] 73 7a [2] 6f 55 }

  condition:
    any of them
}
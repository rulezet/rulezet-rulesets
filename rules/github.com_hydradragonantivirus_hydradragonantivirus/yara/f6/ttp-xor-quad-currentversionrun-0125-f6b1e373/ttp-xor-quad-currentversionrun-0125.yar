rule TTP_XOR_QUAD_CurrentVersionRun_0125 {
  strings:
    $key_0125 = { 52 4a [2] 76 44 [2] 5d 68 [2] 73 4a [2] 67 51 [2] 68 4b [2] 76 56 [2] 74 57 [2] 6f 51 [2] 73 56 [2] 6f 79 }

  condition:
    any of them
}
rule TTP_XOR_QUAD_CurrentVersionRun_01e9 {
  strings:
    $key_01e9 = { 52 86 [2] 76 88 [2] 5d a4 [2] 73 86 [2] 67 9d [2] 68 87 [2] 76 9a [2] 74 9b [2] 6f 9d [2] 73 9a [2] 6f b5 }

  condition:
    any of them
}
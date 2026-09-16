rule TTP_XOR_QUAD_CurrentVersionRun_3af5 {
  strings:
    $key_3af5 = { 69 9a [2] 4d 94 [2] 66 b8 [2] 48 9a [2] 5c 81 [2] 53 9b [2] 4d 86 [2] 4f 87 [2] 54 81 [2] 48 86 [2] 54 a9 }

  condition:
    any of them
}
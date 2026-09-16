rule TTP_XOR_QUAD_CurrentVersionRun_1139 {
  strings:
    $key_1139 = { 42 56 [2] 66 58 [2] 4d 74 [2] 63 56 [2] 77 4d [2] 78 57 [2] 66 4a [2] 64 4b [2] 7f 4d [2] 63 4a [2] 7f 65 }

  condition:
    any of them
}
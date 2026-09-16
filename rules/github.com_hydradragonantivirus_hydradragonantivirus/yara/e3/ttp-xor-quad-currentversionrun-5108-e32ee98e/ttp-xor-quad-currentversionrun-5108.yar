rule TTP_XOR_QUAD_CurrentVersionRun_5108 {
  strings:
    $key_5108 = { 02 67 [2] 26 69 [2] 0d 45 [2] 23 67 [2] 37 7c [2] 38 66 [2] 26 7b [2] 24 7a [2] 3f 7c [2] 23 7b [2] 3f 54 }

  condition:
    any of them
}
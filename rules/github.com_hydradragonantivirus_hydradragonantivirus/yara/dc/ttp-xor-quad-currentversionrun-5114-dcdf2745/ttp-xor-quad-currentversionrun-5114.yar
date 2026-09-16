rule TTP_XOR_QUAD_CurrentVersionRun_5114 {
  strings:
    $key_5114 = { 02 7b [2] 26 75 [2] 0d 59 [2] 23 7b [2] 37 60 [2] 38 7a [2] 26 67 [2] 24 66 [2] 3f 60 [2] 23 67 [2] 3f 48 }

  condition:
    any of them
}
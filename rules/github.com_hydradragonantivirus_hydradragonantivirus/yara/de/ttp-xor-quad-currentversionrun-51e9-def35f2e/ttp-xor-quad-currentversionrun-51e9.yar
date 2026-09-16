rule TTP_XOR_QUAD_CurrentVersionRun_51e9 {
  strings:
    $key_51e9 = { 02 86 [2] 26 88 [2] 0d a4 [2] 23 86 [2] 37 9d [2] 38 87 [2] 26 9a [2] 24 9b [2] 3f 9d [2] 23 9a [2] 3f b5 }

  condition:
    any of them
}
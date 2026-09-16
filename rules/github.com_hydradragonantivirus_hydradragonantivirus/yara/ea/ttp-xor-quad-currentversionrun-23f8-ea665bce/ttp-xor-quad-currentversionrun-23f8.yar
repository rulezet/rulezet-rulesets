rule TTP_XOR_QUAD_CurrentVersionRun_23f8 {
  strings:
    $key_23f8 = { 70 97 [2] 54 99 [2] 7f b5 [2] 51 97 [2] 45 8c [2] 4a 96 [2] 54 8b [2] 56 8a [2] 4d 8c [2] 51 8b [2] 4d a4 }

  condition:
    any of them
}
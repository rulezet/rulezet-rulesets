rule TTP_XOR_QUAD_CurrentVersionRun_7af8 {
  strings:
    $key_7af8 = { 29 97 [2] 0d 99 [2] 26 b5 [2] 08 97 [2] 1c 8c [2] 13 96 [2] 0d 8b [2] 0f 8a [2] 14 8c [2] 08 8b [2] 14 a4 }

  condition:
    any of them
}
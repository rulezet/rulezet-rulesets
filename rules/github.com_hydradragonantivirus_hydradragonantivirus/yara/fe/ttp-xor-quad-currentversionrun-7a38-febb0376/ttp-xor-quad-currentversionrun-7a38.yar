rule TTP_XOR_QUAD_CurrentVersionRun_7a38 {
  strings:
    $key_7a38 = { 29 57 [2] 0d 59 [2] 26 75 [2] 08 57 [2] 1c 4c [2] 13 56 [2] 0d 4b [2] 0f 4a [2] 14 4c [2] 08 4b [2] 14 64 }

  condition:
    any of them
}
rule TTP_XOR_QUAD_CurrentVersionRun_7a15 {
  strings:
    $key_7a15 = { 29 7a [2] 0d 74 [2] 26 58 [2] 08 7a [2] 1c 61 [2] 13 7b [2] 0d 66 [2] 0f 67 [2] 14 61 [2] 08 66 [2] 14 49 }

  condition:
    any of them
}
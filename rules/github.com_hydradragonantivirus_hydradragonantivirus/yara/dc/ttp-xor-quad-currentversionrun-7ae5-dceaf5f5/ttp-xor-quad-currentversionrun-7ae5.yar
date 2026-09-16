rule TTP_XOR_QUAD_CurrentVersionRun_7ae5 {
  strings:
    $key_7ae5 = { 29 8a [2] 0d 84 [2] 26 a8 [2] 08 8a [2] 1c 91 [2] 13 8b [2] 0d 96 [2] 0f 97 [2] 14 91 [2] 08 96 [2] 14 b9 }

  condition:
    any of them
}
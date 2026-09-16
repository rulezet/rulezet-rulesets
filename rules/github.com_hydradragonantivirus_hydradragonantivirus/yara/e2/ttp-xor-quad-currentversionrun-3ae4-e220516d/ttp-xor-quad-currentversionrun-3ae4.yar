rule TTP_XOR_QUAD_CurrentVersionRun_3ae4 {
  strings:
    $key_3ae4 = { 69 8b [2] 4d 85 [2] 66 a9 [2] 48 8b [2] 5c 90 [2] 53 8a [2] 4d 97 [2] 4f 96 [2] 54 90 [2] 48 97 [2] 54 b8 }

  condition:
    any of them
}
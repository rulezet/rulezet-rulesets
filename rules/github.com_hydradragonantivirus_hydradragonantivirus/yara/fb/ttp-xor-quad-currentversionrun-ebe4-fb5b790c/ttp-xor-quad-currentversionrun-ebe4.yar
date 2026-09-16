rule TTP_XOR_QUAD_CurrentVersionRun_ebe4 {
  strings:
    $key_ebe4 = { b8 8b [2] 9c 85 [2] b7 a9 [2] 99 8b [2] 8d 90 [2] 82 8a [2] 9c 97 [2] 9e 96 [2] 85 90 [2] 99 97 [2] 85 b8 }

  condition:
    any of them
}
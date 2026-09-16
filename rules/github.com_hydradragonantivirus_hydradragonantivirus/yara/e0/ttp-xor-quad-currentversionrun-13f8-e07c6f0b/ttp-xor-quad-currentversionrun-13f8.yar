rule TTP_XOR_QUAD_CurrentVersionRun_13f8 {
  strings:
    $key_13f8 = { 40 97 [2] 64 99 [2] 4f b5 [2] 61 97 [2] 75 8c [2] 7a 96 [2] 64 8b [2] 66 8a [2] 7d 8c [2] 61 8b [2] 7d a4 }

  condition:
    any of them
}
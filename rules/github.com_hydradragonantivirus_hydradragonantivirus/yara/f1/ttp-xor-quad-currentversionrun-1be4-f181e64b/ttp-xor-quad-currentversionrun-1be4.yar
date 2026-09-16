rule TTP_XOR_QUAD_CurrentVersionRun_1be4 {
  strings:
    $key_1be4 = { 48 8b [2] 6c 85 [2] 47 a9 [2] 69 8b [2] 7d 90 [2] 72 8a [2] 6c 97 [2] 6e 96 [2] 75 90 [2] 69 97 [2] 75 b8 }

  condition:
    any of them
}
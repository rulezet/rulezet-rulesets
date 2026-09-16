rule TTP_XOR_QUAD_CurrentVersionRun_02e4 {
  strings:
    $key_02e4 = { 51 8b [2] 75 85 [2] 5e a9 [2] 70 8b [2] 64 90 [2] 6b 8a [2] 75 97 [2] 77 96 [2] 6c 90 [2] 70 97 [2] 6c b8 }

  condition:
    any of them
}
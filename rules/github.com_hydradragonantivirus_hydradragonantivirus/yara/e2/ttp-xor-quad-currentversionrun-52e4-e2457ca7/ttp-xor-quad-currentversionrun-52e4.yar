rule TTP_XOR_QUAD_CurrentVersionRun_52e4 {
  strings:
    $key_52e4 = { 01 8b [2] 25 85 [2] 0e a9 [2] 20 8b [2] 34 90 [2] 3b 8a [2] 25 97 [2] 27 96 [2] 3c 90 [2] 20 97 [2] 3c b8 }

  condition:
    any of them
}
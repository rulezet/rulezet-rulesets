rule TTP_XOR_QUAD_CurrentVersionRun_32e4 {
  strings:
    $key_32e4 = { 61 8b [2] 45 85 [2] 6e a9 [2] 40 8b [2] 54 90 [2] 5b 8a [2] 45 97 [2] 47 96 [2] 5c 90 [2] 40 97 [2] 5c b8 }

  condition:
    any of them
}
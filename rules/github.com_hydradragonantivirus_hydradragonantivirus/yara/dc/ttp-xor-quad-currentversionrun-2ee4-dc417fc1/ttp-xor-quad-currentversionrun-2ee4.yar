rule TTP_XOR_QUAD_CurrentVersionRun_2ee4 {
  strings:
    $key_2ee4 = { 7d 8b [2] 59 85 [2] 72 a9 [2] 5c 8b [2] 48 90 [2] 47 8a [2] 59 97 [2] 5b 96 [2] 40 90 [2] 5c 97 [2] 40 b8 }

  condition:
    any of them
}
rule TTP_XOR_QUAD_CurrentVersionRun_2e64 {
  strings:
    $key_2e64 = { 7d 0b [2] 59 05 [2] 72 29 [2] 5c 0b [2] 48 10 [2] 47 0a [2] 59 17 [2] 5b 16 [2] 40 10 [2] 5c 17 [2] 40 38 }

  condition:
    any of them
}
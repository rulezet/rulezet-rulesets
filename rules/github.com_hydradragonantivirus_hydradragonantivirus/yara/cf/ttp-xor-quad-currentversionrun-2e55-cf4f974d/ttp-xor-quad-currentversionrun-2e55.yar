rule TTP_XOR_QUAD_CurrentVersionRun_2e55 {
  strings:
    $key_2e55 = { 7d 3a [2] 59 34 [2] 72 18 [2] 5c 3a [2] 48 21 [2] 47 3b [2] 59 26 [2] 5b 27 [2] 40 21 [2] 5c 26 [2] 40 09 }

  condition:
    any of them
}
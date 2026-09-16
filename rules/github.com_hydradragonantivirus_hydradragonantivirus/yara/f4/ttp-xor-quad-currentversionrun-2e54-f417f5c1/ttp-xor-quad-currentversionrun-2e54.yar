rule TTP_XOR_QUAD_CurrentVersionRun_2e54 {
  strings:
    $key_2e54 = { 7d 3b [2] 59 35 [2] 72 19 [2] 5c 3b [2] 48 20 [2] 47 3a [2] 59 27 [2] 5b 26 [2] 40 20 [2] 5c 27 [2] 40 08 }

  condition:
    any of them
}
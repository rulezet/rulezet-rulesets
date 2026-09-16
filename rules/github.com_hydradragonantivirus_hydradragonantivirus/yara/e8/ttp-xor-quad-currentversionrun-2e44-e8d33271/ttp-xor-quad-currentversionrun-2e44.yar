rule TTP_XOR_QUAD_CurrentVersionRun_2e44 {
  strings:
    $key_2e44 = { 7d 2b [2] 59 25 [2] 72 09 [2] 5c 2b [2] 48 30 [2] 47 2a [2] 59 37 [2] 5b 36 [2] 40 30 [2] 5c 37 [2] 40 18 }

  condition:
    any of them
}
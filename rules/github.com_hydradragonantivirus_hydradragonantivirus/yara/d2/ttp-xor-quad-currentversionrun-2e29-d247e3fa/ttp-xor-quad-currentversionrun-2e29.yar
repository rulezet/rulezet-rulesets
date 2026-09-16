rule TTP_XOR_QUAD_CurrentVersionRun_2e29 {
  strings:
    $key_2e29 = { 7d 46 [2] 59 48 [2] 72 64 [2] 5c 46 [2] 48 5d [2] 47 47 [2] 59 5a [2] 5b 5b [2] 40 5d [2] 5c 5a [2] 40 75 }

  condition:
    any of them
}
rule TTP_XOR_QUAD_CurrentVersionRun_2e14 {
  strings:
    $key_2e14 = { 7d 7b [2] 59 75 [2] 72 59 [2] 5c 7b [2] 48 60 [2] 47 7a [2] 59 67 [2] 5b 66 [2] 40 60 [2] 5c 67 [2] 40 48 }

  condition:
    any of them
}
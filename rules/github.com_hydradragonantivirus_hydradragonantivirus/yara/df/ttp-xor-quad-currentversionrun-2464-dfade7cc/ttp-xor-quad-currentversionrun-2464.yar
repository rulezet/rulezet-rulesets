rule TTP_XOR_QUAD_CurrentVersionRun_2464 {
  strings:
    $key_2464 = { 77 0b [2] 53 05 [2] 78 29 [2] 56 0b [2] 42 10 [2] 4d 0a [2] 53 17 [2] 51 16 [2] 4a 10 [2] 56 17 [2] 4a 38 }

  condition:
    any of them
}
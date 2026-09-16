rule TTP_XOR_QUAD_CurrentVersionRun_2b79 {
  strings:
    $key_2b79 = { 78 16 [2] 5c 18 [2] 77 34 [2] 59 16 [2] 4d 0d [2] 42 17 [2] 5c 0a [2] 5e 0b [2] 45 0d [2] 59 0a [2] 45 25 }

  condition:
    any of them
}
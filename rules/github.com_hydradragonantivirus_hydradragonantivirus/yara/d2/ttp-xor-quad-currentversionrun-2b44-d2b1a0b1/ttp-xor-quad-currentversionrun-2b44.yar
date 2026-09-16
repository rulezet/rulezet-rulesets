rule TTP_XOR_QUAD_CurrentVersionRun_2b44 {
  strings:
    $key_2b44 = { 78 2b [2] 5c 25 [2] 77 09 [2] 59 2b [2] 4d 30 [2] 42 2a [2] 5c 37 [2] 5e 36 [2] 45 30 [2] 59 37 [2] 45 18 }

  condition:
    any of them
}
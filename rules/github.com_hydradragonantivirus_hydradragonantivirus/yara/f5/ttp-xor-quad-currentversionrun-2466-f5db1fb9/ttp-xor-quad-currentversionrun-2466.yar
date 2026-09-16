rule TTP_XOR_QUAD_CurrentVersionRun_2466 {
  strings:
    $key_2466 = { 77 09 [2] 53 07 [2] 78 2b [2] 56 09 [2] 42 12 [2] 4d 08 [2] 53 15 [2] 51 14 [2] 4a 12 [2] 56 15 [2] 4a 3a }

  condition:
    any of them
}
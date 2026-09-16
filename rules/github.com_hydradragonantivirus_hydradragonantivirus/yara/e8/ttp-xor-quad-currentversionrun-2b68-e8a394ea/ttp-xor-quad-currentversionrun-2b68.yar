rule TTP_XOR_QUAD_CurrentVersionRun_2b68 {
  strings:
    $key_2b68 = { 78 07 [2] 5c 09 [2] 77 25 [2] 59 07 [2] 4d 1c [2] 42 06 [2] 5c 1b [2] 5e 1a [2] 45 1c [2] 59 1b [2] 45 34 }

  condition:
    any of them
}
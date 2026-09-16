rule TTP_XOR_QUAD_CurrentVersionRun_2f68 {
  strings:
    $key_2f68 = { 7c 07 [2] 58 09 [2] 73 25 [2] 5d 07 [2] 49 1c [2] 46 06 [2] 58 1b [2] 5a 1a [2] 41 1c [2] 5d 1b [2] 41 34 }

  condition:
    any of them
}
rule TTP_XOR_QUAD_CurrentVersionRun_2874 {
  strings:
    $key_2874 = { 7b 1b [2] 5f 15 [2] 74 39 [2] 5a 1b [2] 4e 00 [2] 41 1a [2] 5f 07 [2] 5d 06 [2] 46 00 [2] 5a 07 [2] 46 28 }

  condition:
    any of them
}
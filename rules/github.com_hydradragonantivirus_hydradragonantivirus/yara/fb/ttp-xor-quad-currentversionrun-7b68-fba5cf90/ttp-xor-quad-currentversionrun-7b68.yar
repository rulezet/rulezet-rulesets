rule TTP_XOR_QUAD_CurrentVersionRun_7b68 {
  strings:
    $key_7b68 = { 28 07 [2] 0c 09 [2] 27 25 [2] 09 07 [2] 1d 1c [2] 12 06 [2] 0c 1b [2] 0e 1a [2] 15 1c [2] 09 1b [2] 15 34 }

  condition:
    any of them
}
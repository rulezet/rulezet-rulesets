rule TTP_XOR_QUAD_CurrentVersionRun_6768 {
  strings:
    $key_6768 = { 34 07 [2] 10 09 [2] 3b 25 [2] 15 07 [2] 01 1c [2] 0e 06 [2] 10 1b [2] 12 1a [2] 09 1c [2] 15 1b [2] 09 34 }

  condition:
    any of them
}
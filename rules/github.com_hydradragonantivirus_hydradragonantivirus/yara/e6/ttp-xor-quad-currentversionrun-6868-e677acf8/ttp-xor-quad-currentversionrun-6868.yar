rule TTP_XOR_QUAD_CurrentVersionRun_6868 {
  strings:
    $key_6868 = { 3b 07 [2] 1f 09 [2] 34 25 [2] 1a 07 [2] 0e 1c [2] 01 06 [2] 1f 1b [2] 1d 1a [2] 06 1c [2] 1a 1b [2] 06 34 }

  condition:
    any of them
}
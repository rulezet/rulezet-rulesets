rule TTP_XOR_QUAD_CurrentVersionRun_5868 {
  strings:
    $key_5868 = { 0b 07 [2] 2f 09 [2] 04 25 [2] 2a 07 [2] 3e 1c [2] 31 06 [2] 2f 1b [2] 2d 1a [2] 36 1c [2] 2a 1b [2] 36 34 }

  condition:
    any of them
}
rule TTP_XOR_QUAD_CurrentVersionRun_4c68 {
  strings:
    $key_4c68 = { 1f 07 [2] 3b 09 [2] 10 25 [2] 3e 07 [2] 2a 1c [2] 25 06 [2] 3b 1b [2] 39 1a [2] 22 1c [2] 3e 1b [2] 22 34 }

  condition:
    any of them
}
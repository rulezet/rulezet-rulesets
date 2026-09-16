rule TTP_XOR_QUAD_CurrentVersionRun_1968 {
  strings:
    $key_1968 = { 4a 07 [2] 6e 09 [2] 45 25 [2] 6b 07 [2] 7f 1c [2] 70 06 [2] 6e 1b [2] 6c 1a [2] 77 1c [2] 6b 1b [2] 77 34 }

  condition:
    any of them
}
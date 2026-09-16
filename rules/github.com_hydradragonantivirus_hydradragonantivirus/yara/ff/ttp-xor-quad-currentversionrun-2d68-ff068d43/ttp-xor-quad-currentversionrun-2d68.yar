rule TTP_XOR_QUAD_CurrentVersionRun_2d68 {
  strings:
    $key_2d68 = { 7e 07 [2] 5a 09 [2] 71 25 [2] 5f 07 [2] 4b 1c [2] 44 06 [2] 5a 1b [2] 58 1a [2] 43 1c [2] 5f 1b [2] 43 34 }

  condition:
    any of them
}
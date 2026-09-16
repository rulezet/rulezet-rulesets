rule TTP_XOR_QUAD_CurrentVersionRun_72f8 {
  strings:
    $key_72f8 = { 21 97 [2] 05 99 [2] 2e b5 [2] 00 97 [2] 14 8c [2] 1b 96 [2] 05 8b [2] 07 8a [2] 1c 8c [2] 00 8b [2] 1c a4 }

  condition:
    any of them
}
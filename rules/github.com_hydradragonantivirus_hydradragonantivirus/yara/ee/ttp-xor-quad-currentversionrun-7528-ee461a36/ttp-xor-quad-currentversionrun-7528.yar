rule TTP_XOR_QUAD_CurrentVersionRun_7528 {
  strings:
    $key_7528 = { 26 47 [2] 02 49 [2] 29 65 [2] 07 47 [2] 13 5c [2] 1c 46 [2] 02 5b [2] 00 5a [2] 1b 5c [2] 07 5b [2] 1b 74 }

  condition:
    any of them
}
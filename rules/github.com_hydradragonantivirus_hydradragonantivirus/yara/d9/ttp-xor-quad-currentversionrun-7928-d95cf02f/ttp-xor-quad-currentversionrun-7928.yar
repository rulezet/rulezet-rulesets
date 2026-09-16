rule TTP_XOR_QUAD_CurrentVersionRun_7928 {
  strings:
    $key_7928 = { 2a 47 [2] 0e 49 [2] 25 65 [2] 0b 47 [2] 1f 5c [2] 10 46 [2] 0e 5b [2] 0c 5a [2] 17 5c [2] 0b 5b [2] 17 74 }

  condition:
    any of them
}
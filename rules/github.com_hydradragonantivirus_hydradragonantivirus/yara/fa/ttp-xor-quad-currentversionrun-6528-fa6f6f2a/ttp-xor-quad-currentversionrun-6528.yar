rule TTP_XOR_QUAD_CurrentVersionRun_6528 {
  strings:
    $key_6528 = { 36 47 [2] 12 49 [2] 39 65 [2] 17 47 [2] 03 5c [2] 0c 46 [2] 12 5b [2] 10 5a [2] 0b 5c [2] 17 5b [2] 0b 74 }

  condition:
    any of them
}
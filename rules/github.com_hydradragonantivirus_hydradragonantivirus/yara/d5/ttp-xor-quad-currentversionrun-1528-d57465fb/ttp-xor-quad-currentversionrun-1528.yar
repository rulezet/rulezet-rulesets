rule TTP_XOR_QUAD_CurrentVersionRun_1528 {
  strings:
    $key_1528 = { 46 47 [2] 62 49 [2] 49 65 [2] 67 47 [2] 73 5c [2] 7c 46 [2] 62 5b [2] 60 5a [2] 7b 5c [2] 67 5b [2] 7b 74 }

  condition:
    any of them
}
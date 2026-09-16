rule TTP_XOR_QUAD_CurrentVersionRun_1538 {
  strings:
    $key_1538 = { 46 57 [2] 62 59 [2] 49 75 [2] 67 57 [2] 73 4c [2] 7c 56 [2] 62 4b [2] 60 4a [2] 7b 4c [2] 67 4b [2] 7b 64 }

  condition:
    any of them
}
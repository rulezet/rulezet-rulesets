rule TTP_XOR_QUAD_CurrentVersionRun_2f28 {
  strings:
    $key_2f28 = { 7c 47 [2] 58 49 [2] 73 65 [2] 5d 47 [2] 49 5c [2] 46 46 [2] 58 5b [2] 5a 5a [2] 41 5c [2] 5d 5b [2] 41 74 }

  condition:
    any of them
}
rule TTP_XOR_QUAD_CurrentVersionRun_2a35 {
  strings:
    $key_2a35 = { 79 5a [2] 5d 54 [2] 76 78 [2] 58 5a [2] 4c 41 [2] 43 5b [2] 5d 46 [2] 5f 47 [2] 44 41 [2] 58 46 [2] 44 69 }

  condition:
    any of them
}
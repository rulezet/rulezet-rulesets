rule TTP_XOR_QUAD_CurrentVersionRun_2f09 {
  strings:
    $key_2f09 = { 7c 66 [2] 58 68 [2] 73 44 [2] 5d 66 [2] 49 7d [2] 46 67 [2] 58 7a [2] 5a 7b [2] 41 7d [2] 5d 7a [2] 41 55 }

  condition:
    any of them
}
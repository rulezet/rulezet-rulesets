rule TTP_XOR_QUAD_CurrentVersionRun_2ff9 {
  strings:
    $key_2ff9 = { 7c 96 [2] 58 98 [2] 73 b4 [2] 5d 96 [2] 49 8d [2] 46 97 [2] 58 8a [2] 5a 8b [2] 41 8d [2] 5d 8a [2] 41 a5 }

  condition:
    any of them
}
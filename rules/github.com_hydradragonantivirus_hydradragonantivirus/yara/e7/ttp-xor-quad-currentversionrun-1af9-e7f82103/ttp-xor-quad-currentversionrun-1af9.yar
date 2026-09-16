rule TTP_XOR_QUAD_CurrentVersionRun_1af9 {
  strings:
    $key_1af9 = { 49 96 [2] 6d 98 [2] 46 b4 [2] 68 96 [2] 7c 8d [2] 73 97 [2] 6d 8a [2] 6f 8b [2] 74 8d [2] 68 8a [2] 74 a5 }

  condition:
    any of them
}
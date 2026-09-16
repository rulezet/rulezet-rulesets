rule TTP_XOR_QUAD_CurrentVersionRun_1ff9 {
  strings:
    $key_1ff9 = { 4c 96 [2] 68 98 [2] 43 b4 [2] 6d 96 [2] 79 8d [2] 76 97 [2] 68 8a [2] 6a 8b [2] 71 8d [2] 6d 8a [2] 71 a5 }

  condition:
    any of them
}
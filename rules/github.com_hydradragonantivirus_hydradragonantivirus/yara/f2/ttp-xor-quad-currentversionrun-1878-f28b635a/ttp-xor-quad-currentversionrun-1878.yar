rule TTP_XOR_QUAD_CurrentVersionRun_1878 {
  strings:
    $key_1878 = { 4b 17 [2] 6f 19 [2] 44 35 [2] 6a 17 [2] 7e 0c [2] 71 16 [2] 6f 0b [2] 6d 0a [2] 76 0c [2] 6a 0b [2] 76 24 }

  condition:
    any of them
}
rule TTP_XOR_QUAD_CurrentVersionRun_1578 {
  strings:
    $key_1578 = { 46 17 [2] 62 19 [2] 49 35 [2] 67 17 [2] 73 0c [2] 7c 16 [2] 62 0b [2] 60 0a [2] 7b 0c [2] 67 0b [2] 7b 24 }

  condition:
    any of them
}
rule TTP_XOR_QUAD_CurrentVersionRun_7915 {
  strings:
    $key_7915 = { 2a 7a [2] 0e 74 [2] 25 58 [2] 0b 7a [2] 1f 61 [2] 10 7b [2] 0e 66 [2] 0c 67 [2] 17 61 [2] 0b 66 [2] 17 49 }

  condition:
    any of them
}
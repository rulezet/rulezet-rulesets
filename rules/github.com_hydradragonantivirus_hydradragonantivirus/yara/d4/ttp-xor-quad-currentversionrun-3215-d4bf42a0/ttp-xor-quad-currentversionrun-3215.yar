rule TTP_XOR_QUAD_CurrentVersionRun_3215 {
  strings:
    $key_3215 = { 61 7a [2] 45 74 [2] 6e 58 [2] 40 7a [2] 54 61 [2] 5b 7b [2] 45 66 [2] 47 67 [2] 5c 61 [2] 40 66 [2] 5c 49 }

  condition:
    any of them
}
rule TTP_XOR_QUAD_CurrentVersionRun_6215 {
  strings:
    $key_6215 = { 31 7a [2] 15 74 [2] 3e 58 [2] 10 7a [2] 04 61 [2] 0b 7b [2] 15 66 [2] 17 67 [2] 0c 61 [2] 10 66 [2] 0c 49 }

  condition:
    any of them
}
rule TTP_XOR_QUAD_CurrentVersionRun_7d09 {
  strings:
    $key_7d09 = { 2e 66 [2] 0a 68 [2] 21 44 [2] 0f 66 [2] 1b 7d [2] 14 67 [2] 0a 7a [2] 08 7b [2] 13 7d [2] 0f 7a [2] 13 55 }

  condition:
    any of them
}
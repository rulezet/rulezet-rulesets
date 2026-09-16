rule TTP_XOR_QUAD_CurrentVersionRun_0937 {
  strings:
    $key_0937 = { 5a 58 [2] 7e 56 [2] 55 7a [2] 7b 58 [2] 6f 43 [2] 60 59 [2] 7e 44 [2] 7c 45 [2] 67 43 [2] 7b 44 [2] 67 6b }

  condition:
    any of them
}
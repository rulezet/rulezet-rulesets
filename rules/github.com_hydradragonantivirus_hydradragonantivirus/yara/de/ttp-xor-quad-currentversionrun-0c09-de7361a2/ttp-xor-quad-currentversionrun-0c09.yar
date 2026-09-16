rule TTP_XOR_QUAD_CurrentVersionRun_0c09 {
  strings:
    $key_0c09 = { 5f 66 [2] 7b 68 [2] 50 44 [2] 7e 66 [2] 6a 7d [2] 65 67 [2] 7b 7a [2] 79 7b [2] 62 7d [2] 7e 7a [2] 62 55 }

  condition:
    any of them
}
rule TTP_XOR_QUAD_CurrentVersionRun_0e09 {
  strings:
    $key_0e09 = { 5d 66 [2] 79 68 [2] 52 44 [2] 7c 66 [2] 68 7d [2] 67 67 [2] 79 7a [2] 7b 7b [2] 60 7d [2] 7c 7a [2] 60 55 }

  condition:
    any of them
}
rule TTP_XOR_QUAD_CurrentVersionRun_6ce9 {
  strings:
    $key_6ce9 = { 3f 86 [2] 1b 88 [2] 30 a4 [2] 1e 86 [2] 0a 9d [2] 05 87 [2] 1b 9a [2] 19 9b [2] 02 9d [2] 1e 9a [2] 02 b5 }

  condition:
    any of them
}
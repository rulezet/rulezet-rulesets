rule TTP_XOR_QUAD_CurrentVersionRun_6ce8 {
  strings:
    $key_6ce8 = { 3f 87 [2] 1b 89 [2] 30 a5 [2] 1e 87 [2] 0a 9c [2] 05 86 [2] 1b 9b [2] 19 9a [2] 02 9c [2] 1e 9b [2] 02 b4 }

  condition:
    any of them
}
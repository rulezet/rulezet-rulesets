rule TTP_XOR_QUAD_CurrentVersionRun_49e9 {
  strings:
    $key_49e9 = { 1a 86 [2] 3e 88 [2] 15 a4 [2] 3b 86 [2] 2f 9d [2] 20 87 [2] 3e 9a [2] 3c 9b [2] 27 9d [2] 3b 9a [2] 27 b5 }

  condition:
    any of them
}
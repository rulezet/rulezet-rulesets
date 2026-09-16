rule TTP_XOR_QUAD_CurrentVersionRun_1be9 {
  strings:
    $key_1be9 = { 48 86 [2] 6c 88 [2] 47 a4 [2] 69 86 [2] 7d 9d [2] 72 87 [2] 6c 9a [2] 6e 9b [2] 75 9d [2] 69 9a [2] 75 b5 }

  condition:
    any of them
}
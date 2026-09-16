rule TTP_XOR_QUAD_CurrentVersionRun_22e9 {
  strings:
    $key_22e9 = { 71 86 [2] 55 88 [2] 7e a4 [2] 50 86 [2] 44 9d [2] 4b 87 [2] 55 9a [2] 57 9b [2] 4c 9d [2] 50 9a [2] 4c b5 }

  condition:
    any of them
}
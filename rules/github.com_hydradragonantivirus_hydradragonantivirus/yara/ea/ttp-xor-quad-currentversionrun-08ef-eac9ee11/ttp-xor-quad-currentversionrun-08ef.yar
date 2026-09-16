rule TTP_XOR_QUAD_CurrentVersionRun_08ef {
  strings:
    $key_08ef = { 5b 80 [2] 7f 8e [2] 54 a2 [2] 7a 80 [2] 6e 9b [2] 61 81 [2] 7f 9c [2] 7d 9d [2] 66 9b [2] 7a 9c [2] 66 b3 }

  condition:
    any of them
}
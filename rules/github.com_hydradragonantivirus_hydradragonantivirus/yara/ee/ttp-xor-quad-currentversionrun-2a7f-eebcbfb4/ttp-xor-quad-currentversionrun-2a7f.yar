rule TTP_XOR_QUAD_CurrentVersionRun_2a7f {
  strings:
    $key_2a7f = { 79 10 [2] 5d 1e [2] 76 32 [2] 58 10 [2] 4c 0b [2] 43 11 [2] 5d 0c [2] 5f 0d [2] 44 0b [2] 58 0c [2] 44 23 }

  condition:
    any of them
}
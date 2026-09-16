rule TTP_XOR_QUAD_CurrentVersionRun_2aef {
  strings:
    $key_2aef = { 79 80 [2] 5d 8e [2] 76 a2 [2] 58 80 [2] 4c 9b [2] 43 81 [2] 5d 9c [2] 5f 9d [2] 44 9b [2] 58 9c [2] 44 b3 }

  condition:
    any of them
}
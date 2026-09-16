rule TTP_XOR_QUAD_CurrentVersionRun_28ef {
  strings:
    $key_28ef = { 7b 80 [2] 5f 8e [2] 74 a2 [2] 5a 80 [2] 4e 9b [2] 41 81 [2] 5f 9c [2] 5d 9d [2] 46 9b [2] 5a 9c [2] 46 b3 }

  condition:
    any of them
}
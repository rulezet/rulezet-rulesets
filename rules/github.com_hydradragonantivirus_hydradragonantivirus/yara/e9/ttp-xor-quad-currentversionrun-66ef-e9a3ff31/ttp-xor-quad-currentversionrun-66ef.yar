rule TTP_XOR_QUAD_CurrentVersionRun_66ef {
  strings:
    $key_66ef = { 35 80 [2] 11 8e [2] 3a a2 [2] 14 80 [2] 00 9b [2] 0f 81 [2] 11 9c [2] 13 9d [2] 08 9b [2] 14 9c [2] 08 b3 }

  condition:
    any of them
}
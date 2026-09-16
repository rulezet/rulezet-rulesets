rule TTP_XOR_QUAD_CurrentVersionRun_25ef {
  strings:
    $key_25ef = { 76 80 [2] 52 8e [2] 79 a2 [2] 57 80 [2] 43 9b [2] 4c 81 [2] 52 9c [2] 50 9d [2] 4b 9b [2] 57 9c [2] 4b b3 }

  condition:
    any of them
}
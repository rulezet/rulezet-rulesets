rule TTP_XOR_QUAD_CurrentVersionRun_31ef {
  strings:
    $key_31ef = { 62 80 [2] 46 8e [2] 6d a2 [2] 43 80 [2] 57 9b [2] 58 81 [2] 46 9c [2] 44 9d [2] 5f 9b [2] 43 9c [2] 5f b3 }

  condition:
    any of them
}
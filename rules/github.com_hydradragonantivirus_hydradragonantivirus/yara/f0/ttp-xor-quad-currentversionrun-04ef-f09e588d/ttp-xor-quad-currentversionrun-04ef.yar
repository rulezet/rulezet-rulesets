rule TTP_XOR_QUAD_CurrentVersionRun_04ef {
  strings:
    $key_04ef = { 57 80 [2] 73 8e [2] 58 a2 [2] 76 80 [2] 62 9b [2] 6d 81 [2] 73 9c [2] 71 9d [2] 6a 9b [2] 76 9c [2] 6a b3 }

  condition:
    any of them
}
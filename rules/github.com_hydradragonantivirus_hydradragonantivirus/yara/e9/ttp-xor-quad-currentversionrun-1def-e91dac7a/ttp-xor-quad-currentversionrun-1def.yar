rule TTP_XOR_QUAD_CurrentVersionRun_1def {
  strings:
    $key_1def = { 4e 80 [2] 6a 8e [2] 41 a2 [2] 6f 80 [2] 7b 9b [2] 74 81 [2] 6a 9c [2] 68 9d [2] 73 9b [2] 6f 9c [2] 73 b3 }

  condition:
    any of them
}
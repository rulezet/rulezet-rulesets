rule TTP_XOR_QUAD_CurrentVersionRun_efb7 {
  strings:
    $key_efb7 = { bc d8 [2] 98 d6 [2] b3 fa [2] 9d d8 [2] 89 c3 [2] 86 d9 [2] 98 c4 [2] 9a c5 [2] 81 c3 [2] 9d c4 [2] 81 eb }

  condition:
    any of them
}
rule TTP_XOR_QUAD_CurrentVersionRun_f1aa {
  strings:
    $key_f1aa = { a2 c5 [2] 86 cb [2] ad e7 [2] 83 c5 [2] 97 de [2] 98 c4 [2] 86 d9 [2] 84 d8 [2] 9f de [2] 83 d9 [2] 9f f6 }

  condition:
    any of them
}
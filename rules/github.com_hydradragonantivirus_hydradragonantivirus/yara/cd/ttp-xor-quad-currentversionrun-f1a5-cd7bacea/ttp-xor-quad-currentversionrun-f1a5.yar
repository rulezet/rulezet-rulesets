rule TTP_XOR_QUAD_CurrentVersionRun_f1a5 {
  strings:
    $key_f1a5 = { a2 ca [2] 86 c4 [2] ad e8 [2] 83 ca [2] 97 d1 [2] 98 cb [2] 86 d6 [2] 84 d7 [2] 9f d1 [2] 83 d6 [2] 9f f9 }

  condition:
    any of them
}
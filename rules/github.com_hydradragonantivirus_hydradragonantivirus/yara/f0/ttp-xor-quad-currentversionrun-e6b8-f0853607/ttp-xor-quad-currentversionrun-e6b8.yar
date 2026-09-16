rule TTP_XOR_QUAD_CurrentVersionRun_e6b8 {
  strings:
    $key_e6b8 = { b5 d7 [2] 91 d9 [2] ba f5 [2] 94 d7 [2] 80 cc [2] 8f d6 [2] 91 cb [2] 93 ca [2] 88 cc [2] 94 cb [2] 88 e4 }

  condition:
    any of them
}
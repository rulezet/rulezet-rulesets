rule TTP_XOR_QUAD_CurrentVersionRun_a9a4 {
  strings:
    $key_a9a4 = { fa cb [2] de c5 [2] f5 e9 [2] db cb [2] cf d0 [2] c0 ca [2] de d7 [2] dc d6 [2] c7 d0 [2] db d7 [2] c7 f8 }

  condition:
    any of them
}
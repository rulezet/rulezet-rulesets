rule TTP_XOR_QUAD_CurrentVersionRun_95b9 {
  strings:
    $key_95b9 = { c6 d6 [2] e2 d8 [2] c9 f4 [2] e7 d6 [2] f3 cd [2] fc d7 [2] e2 ca [2] e0 cb [2] fb cd [2] e7 ca [2] fb e5 }

  condition:
    any of them
}
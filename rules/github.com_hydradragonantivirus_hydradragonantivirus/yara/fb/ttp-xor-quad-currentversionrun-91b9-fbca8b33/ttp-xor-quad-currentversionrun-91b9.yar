rule TTP_XOR_QUAD_CurrentVersionRun_91b9 {
  strings:
    $key_91b9 = { c2 d6 [2] e6 d8 [2] cd f4 [2] e3 d6 [2] f7 cd [2] f8 d7 [2] e6 ca [2] e4 cb [2] ff cd [2] e3 ca [2] ff e5 }

  condition:
    any of them
}
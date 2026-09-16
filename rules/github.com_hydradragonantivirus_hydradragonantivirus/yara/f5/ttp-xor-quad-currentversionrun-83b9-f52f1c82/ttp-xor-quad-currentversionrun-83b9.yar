rule TTP_XOR_QUAD_CurrentVersionRun_83b9 {
  strings:
    $key_83b9 = { d0 d6 [2] f4 d8 [2] df f4 [2] f1 d6 [2] e5 cd [2] ea d7 [2] f4 ca [2] f6 cb [2] ed cd [2] f1 ca [2] ed e5 }

  condition:
    any of them
}
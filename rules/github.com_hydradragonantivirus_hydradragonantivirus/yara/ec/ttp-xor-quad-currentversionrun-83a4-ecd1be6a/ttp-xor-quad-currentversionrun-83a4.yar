rule TTP_XOR_QUAD_CurrentVersionRun_83a4 {
  strings:
    $key_83a4 = { d0 cb [2] f4 c5 [2] df e9 [2] f1 cb [2] e5 d0 [2] ea ca [2] f4 d7 [2] f6 d6 [2] ed d0 [2] f1 d7 [2] ed f8 }

  condition:
    any of them
}
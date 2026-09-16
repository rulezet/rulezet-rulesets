rule TTP_XOR_QUAD_CurrentVersionRun_84b9 {
  strings:
    $key_84b9 = { d7 d6 [2] f3 d8 [2] d8 f4 [2] f6 d6 [2] e2 cd [2] ed d7 [2] f3 ca [2] f1 cb [2] ea cd [2] f6 ca [2] ea e5 }

  condition:
    any of them
}
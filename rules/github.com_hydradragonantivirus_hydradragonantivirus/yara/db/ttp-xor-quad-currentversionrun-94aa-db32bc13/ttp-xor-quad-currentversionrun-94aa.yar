rule TTP_XOR_QUAD_CurrentVersionRun_94aa {
  strings:
    $key_94aa = { c7 c5 [2] e3 cb [2] c8 e7 [2] e6 c5 [2] f2 de [2] fd c4 [2] e3 d9 [2] e1 d8 [2] fa de [2] e6 d9 [2] fa f6 }

  condition:
    any of them
}
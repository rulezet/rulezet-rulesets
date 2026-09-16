rule TTP_XOR_QUAD_CurrentVersionRun_8ea5 {
  strings:
    $key_8ea5 = { dd ca [2] f9 c4 [2] d2 e8 [2] fc ca [2] e8 d1 [2] e7 cb [2] f9 d6 [2] fb d7 [2] e0 d1 [2] fc d6 [2] e0 f9 }

  condition:
    any of them
}
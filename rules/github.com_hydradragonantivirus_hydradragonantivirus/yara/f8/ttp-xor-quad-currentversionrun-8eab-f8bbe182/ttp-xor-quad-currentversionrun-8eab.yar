rule TTP_XOR_QUAD_CurrentVersionRun_8eab {
  strings:
    $key_8eab = { dd c4 [2] f9 ca [2] d2 e6 [2] fc c4 [2] e8 df [2] e7 c5 [2] f9 d8 [2] fb d9 [2] e0 df [2] fc d8 [2] e0 f7 }

  condition:
    any of them
}
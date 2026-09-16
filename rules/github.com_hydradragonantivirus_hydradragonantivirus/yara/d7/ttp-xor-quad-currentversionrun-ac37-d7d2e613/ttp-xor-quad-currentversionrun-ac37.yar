rule TTP_XOR_QUAD_CurrentVersionRun_ac37 {
  strings:
    $key_ac37 = { ff 58 [2] db 56 [2] f0 7a [2] de 58 [2] ca 43 [2] c5 59 [2] db 44 [2] d9 45 [2] c2 43 [2] de 44 [2] c2 6b }

  condition:
    any of them
}
rule TTP_XOR_QUAD_CurrentVersionRun_ac55 {
  strings:
    $key_ac55 = { ff 3a [2] db 34 [2] f0 18 [2] de 3a [2] ca 21 [2] c5 3b [2] db 26 [2] d9 27 [2] c2 21 [2] de 26 [2] c2 09 }

  condition:
    any of them
}
rule TTP_XOR_QUAD_CurrentVersionRun_ac64 {
  strings:
    $key_ac64 = { ff 0b [2] db 05 [2] f0 29 [2] de 0b [2] ca 10 [2] c5 0a [2] db 17 [2] d9 16 [2] c2 10 [2] de 17 [2] c2 38 }

  condition:
    any of them
}
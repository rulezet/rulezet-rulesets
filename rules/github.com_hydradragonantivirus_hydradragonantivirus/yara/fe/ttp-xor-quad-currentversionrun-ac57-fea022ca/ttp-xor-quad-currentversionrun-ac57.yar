rule TTP_XOR_QUAD_CurrentVersionRun_ac57 {
  strings:
    $key_ac57 = { ff 38 [2] db 36 [2] f0 1a [2] de 38 [2] ca 23 [2] c5 39 [2] db 24 [2] d9 25 [2] c2 23 [2] de 24 [2] c2 0b }

  condition:
    any of them
}
rule TTP_XOR_QUAD_CurrentVersionRun_ac1a {
  strings:
    $key_ac1a = { ff 75 [2] db 7b [2] f0 57 [2] de 75 [2] ca 6e [2] c5 74 [2] db 69 [2] d9 68 [2] c2 6e [2] de 69 [2] c2 46 }

  condition:
    any of them
}
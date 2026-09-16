rule TTP_XOR_QUAD_CurrentVersionRun_ac18 {
  strings:
    $key_ac18 = { ff 77 [2] db 79 [2] f0 55 [2] de 77 [2] ca 6c [2] c5 76 [2] db 6b [2] d9 6a [2] c2 6c [2] de 6b [2] c2 44 }

  condition:
    any of them
}
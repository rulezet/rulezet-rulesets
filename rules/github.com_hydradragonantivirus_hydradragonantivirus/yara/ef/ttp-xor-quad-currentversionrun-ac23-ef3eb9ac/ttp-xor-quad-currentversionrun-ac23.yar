rule TTP_XOR_QUAD_CurrentVersionRun_ac23 {
  strings:
    $key_ac23 = { ff 4c [2] db 42 [2] f0 6e [2] de 4c [2] ca 57 [2] c5 4d [2] db 50 [2] d9 51 [2] c2 57 [2] de 50 [2] c2 7f }

  condition:
    any of them
}
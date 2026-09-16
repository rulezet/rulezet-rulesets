rule TTP_XOR_QUAD_CurrentVersionRun_ac13 {
  strings:
    $key_ac13 = { ff 7c [2] db 72 [2] f0 5e [2] de 7c [2] ca 67 [2] c5 7d [2] db 60 [2] d9 61 [2] c2 67 [2] de 60 [2] c2 4f }

  condition:
    any of them
}
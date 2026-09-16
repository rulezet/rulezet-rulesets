rule TTP_XOR_QUAD_CurrentVersionRun_ac51 {
  strings:
    $key_ac51 = { ff 3e [2] db 30 [2] f0 1c [2] de 3e [2] ca 25 [2] c5 3f [2] db 22 [2] d9 23 [2] c2 25 [2] de 22 [2] c2 0d }

  condition:
    any of them
}
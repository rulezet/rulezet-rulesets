rule TTP_XOR_QUAD_CurrentVersionRun_ac61 {
  strings:
    $key_ac61 = { ff 0e [2] db 00 [2] f0 2c [2] de 0e [2] ca 15 [2] c5 0f [2] db 12 [2] d9 13 [2] c2 15 [2] de 12 [2] c2 3d }

  condition:
    any of them
}
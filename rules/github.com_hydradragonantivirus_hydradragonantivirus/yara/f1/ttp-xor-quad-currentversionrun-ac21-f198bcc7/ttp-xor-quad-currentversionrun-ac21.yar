rule TTP_XOR_QUAD_CurrentVersionRun_ac21 {
  strings:
    $key_ac21 = { ff 4e [2] db 40 [2] f0 6c [2] de 4e [2] ca 55 [2] c5 4f [2] db 52 [2] d9 53 [2] c2 55 [2] de 52 [2] c2 7d }

  condition:
    any of them
}
rule TTP_XOR_QUAD_CurrentVersionRun_ac50 {
  strings:
    $key_ac50 = { ff 3f [2] db 31 [2] f0 1d [2] de 3f [2] ca 24 [2] c5 3e [2] db 23 [2] d9 22 [2] c2 24 [2] de 23 [2] c2 0c }

  condition:
    any of them
}
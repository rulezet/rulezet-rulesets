rule TTP_XOR_QUAD_CurrentVersionRun_ac4c {
  strings:
    $key_ac4c = { ff 23 [2] db 2d [2] f0 01 [2] de 23 [2] ca 38 [2] c5 22 [2] db 3f [2] d9 3e [2] c2 38 [2] de 3f [2] c2 10 }

  condition:
    any of them
}
rule TTP_XOR_QUAD_CurrentVersionRun_ac6d {
  strings:
    $key_ac6d = { ff 02 [2] db 0c [2] f0 20 [2] de 02 [2] ca 19 [2] c5 03 [2] db 1e [2] d9 1f [2] c2 19 [2] de 1e [2] c2 31 }

  condition:
    any of them
}
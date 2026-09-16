rule TTP_XOR_QUAD_CurrentVersionRun_ac6e {
  strings:
    $key_ac6e = { ff 01 [2] db 0f [2] f0 23 [2] de 01 [2] ca 1a [2] c5 00 [2] db 1d [2] d9 1c [2] c2 1a [2] de 1d [2] c2 32 }

  condition:
    any of them
}
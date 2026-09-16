rule TTP_XOR_QUAD_CurrentVersionRun_ac44 {
  strings:
    $key_ac44 = { ff 2b [2] db 25 [2] f0 09 [2] de 2b [2] ca 30 [2] c5 2a [2] db 37 [2] d9 36 [2] c2 30 [2] de 37 [2] c2 18 }

  condition:
    any of them
}
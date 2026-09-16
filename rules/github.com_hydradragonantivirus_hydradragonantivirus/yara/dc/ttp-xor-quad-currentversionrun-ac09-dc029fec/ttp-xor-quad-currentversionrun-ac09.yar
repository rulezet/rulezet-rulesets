rule TTP_XOR_QUAD_CurrentVersionRun_ac09 {
  strings:
    $key_ac09 = { ff 66 [2] db 68 [2] f0 44 [2] de 66 [2] ca 7d [2] c5 67 [2] db 7a [2] d9 7b [2] c2 7d [2] de 7a [2] c2 55 }

  condition:
    any of them
}
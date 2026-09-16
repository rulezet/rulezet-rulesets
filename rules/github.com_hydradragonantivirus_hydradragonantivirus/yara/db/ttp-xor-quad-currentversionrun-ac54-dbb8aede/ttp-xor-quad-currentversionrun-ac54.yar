rule TTP_XOR_QUAD_CurrentVersionRun_ac54 {
  strings:
    $key_ac54 = { ff 3b [2] db 35 [2] f0 19 [2] de 3b [2] ca 20 [2] c5 3a [2] db 27 [2] d9 26 [2] c2 20 [2] de 27 [2] c2 08 }

  condition:
    any of them
}
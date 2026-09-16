rule TTP_XOR_QUAD_CurrentVersionRun_ac7c {
  strings:
    $key_ac7c = { ff 13 [2] db 1d [2] f0 31 [2] de 13 [2] ca 08 [2] c5 12 [2] db 0f [2] d9 0e [2] c2 08 [2] de 0f [2] c2 20 }

  condition:
    any of them
}
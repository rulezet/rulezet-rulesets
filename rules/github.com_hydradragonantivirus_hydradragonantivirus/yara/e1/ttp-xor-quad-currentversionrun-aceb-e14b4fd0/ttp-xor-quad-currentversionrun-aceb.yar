rule TTP_XOR_QUAD_CurrentVersionRun_aceb {
  strings:
    $key_aceb = { ff 84 [2] db 8a [2] f0 a6 [2] de 84 [2] ca 9f [2] c5 85 [2] db 98 [2] d9 99 [2] c2 9f [2] de 98 [2] c2 b7 }

  condition:
    any of them
}
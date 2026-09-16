rule TTP_XOR_QUAD_CurrentVersionRun_acee {
  strings:
    $key_acee = { ff 81 [2] db 8f [2] f0 a3 [2] de 81 [2] ca 9a [2] c5 80 [2] db 9d [2] d9 9c [2] c2 9a [2] de 9d [2] c2 b2 }

  condition:
    any of them
}
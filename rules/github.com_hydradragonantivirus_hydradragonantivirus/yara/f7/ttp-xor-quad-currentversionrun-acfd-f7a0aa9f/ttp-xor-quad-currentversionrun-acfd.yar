rule TTP_XOR_QUAD_CurrentVersionRun_acfd {
  strings:
    $key_acfd = { ff 92 [2] db 9c [2] f0 b0 [2] de 92 [2] ca 89 [2] c5 93 [2] db 8e [2] d9 8f [2] c2 89 [2] de 8e [2] c2 a1 }

  condition:
    any of them
}
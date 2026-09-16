rule TTP_XOR_QUAD_CurrentVersionRun_acfb {
  strings:
    $key_acfb = { ff 94 [2] db 9a [2] f0 b6 [2] de 94 [2] ca 8f [2] c5 95 [2] db 88 [2] d9 89 [2] c2 8f [2] de 88 [2] c2 a7 }

  condition:
    any of them
}
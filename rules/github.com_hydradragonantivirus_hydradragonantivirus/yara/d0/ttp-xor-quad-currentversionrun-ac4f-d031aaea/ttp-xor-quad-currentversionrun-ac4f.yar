rule TTP_XOR_QUAD_CurrentVersionRun_ac4f {
  strings:
    $key_ac4f = { ff 20 [2] db 2e [2] f0 02 [2] de 20 [2] ca 3b [2] c5 21 [2] db 3c [2] d9 3d [2] c2 3b [2] de 3c [2] c2 13 }

  condition:
    any of them
}
rule TTP_XOR_QUAD_CurrentVersionRun_ac1e {
  strings:
    $key_ac1e = { ff 71 [2] db 7f [2] f0 53 [2] de 71 [2] ca 6a [2] c5 70 [2] db 6d [2] d9 6c [2] c2 6a [2] de 6d [2] c2 42 }

  condition:
    any of them
}
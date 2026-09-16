rule TTP_XOR_QUAD_CurrentVersionRun_ac3d {
  strings:
    $key_ac3d = { ff 52 [2] db 5c [2] f0 70 [2] de 52 [2] ca 49 [2] c5 53 [2] db 4e [2] d9 4f [2] c2 49 [2] de 4e [2] c2 61 }

  condition:
    any of them
}
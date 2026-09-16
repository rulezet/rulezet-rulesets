rule TTP_XOR_QUAD_CurrentVersionRun_ac22 {
  strings:
    $key_ac22 = { ff 4d [2] db 43 [2] f0 6f [2] de 4d [2] ca 56 [2] c5 4c [2] db 51 [2] d9 50 [2] c2 56 [2] de 51 [2] c2 7e }

  condition:
    any of them
}
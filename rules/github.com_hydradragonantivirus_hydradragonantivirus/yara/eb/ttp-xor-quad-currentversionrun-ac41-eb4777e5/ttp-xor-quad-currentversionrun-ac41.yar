rule TTP_XOR_QUAD_CurrentVersionRun_ac41 {
  strings:
    $key_ac41 = { ff 2e [2] db 20 [2] f0 0c [2] de 2e [2] ca 35 [2] c5 2f [2] db 32 [2] d9 33 [2] c2 35 [2] de 32 [2] c2 1d }

  condition:
    any of them
}
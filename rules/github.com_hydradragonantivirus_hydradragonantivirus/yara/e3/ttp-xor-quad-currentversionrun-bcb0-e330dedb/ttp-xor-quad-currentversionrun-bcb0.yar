rule TTP_XOR_QUAD_CurrentVersionRun_bcb0 {
  strings:
    $key_bcb0 = { ef df [2] cb d1 [2] e0 fd [2] ce df [2] da c4 [2] d5 de [2] cb c3 [2] c9 c2 [2] d2 c4 [2] ce c3 [2] d2 ec }

  condition:
    any of them
}
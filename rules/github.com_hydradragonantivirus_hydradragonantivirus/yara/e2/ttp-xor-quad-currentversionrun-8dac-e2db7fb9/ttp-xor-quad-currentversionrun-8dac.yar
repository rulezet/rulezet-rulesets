rule TTP_XOR_QUAD_CurrentVersionRun_8dac {
  strings:
    $key_8dac = { de c3 [2] fa cd [2] d1 e1 [2] ff c3 [2] eb d8 [2] e4 c2 [2] fa df [2] f8 de [2] e3 d8 [2] ff df [2] e3 f0 }

  condition:
    any of them
}
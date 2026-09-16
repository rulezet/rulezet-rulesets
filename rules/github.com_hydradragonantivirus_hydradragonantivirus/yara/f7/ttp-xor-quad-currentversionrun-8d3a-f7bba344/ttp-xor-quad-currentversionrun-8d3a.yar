rule TTP_XOR_QUAD_CurrentVersionRun_8d3a {
  strings:
    $key_8d3a = { de 55 [2] fa 5b [2] d1 77 [2] ff 55 [2] eb 4e [2] e4 54 [2] fa 49 [2] f8 48 [2] e3 4e [2] ff 49 [2] e3 66 }

  condition:
    any of them
}
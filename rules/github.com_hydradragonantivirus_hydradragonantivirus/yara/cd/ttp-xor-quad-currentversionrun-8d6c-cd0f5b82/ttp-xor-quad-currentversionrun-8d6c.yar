rule TTP_XOR_QUAD_CurrentVersionRun_8d6c {
  strings:
    $key_8d6c = { de 03 [2] fa 0d [2] d1 21 [2] ff 03 [2] eb 18 [2] e4 02 [2] fa 1f [2] f8 1e [2] e3 18 [2] ff 1f [2] e3 30 }

  condition:
    any of them
}
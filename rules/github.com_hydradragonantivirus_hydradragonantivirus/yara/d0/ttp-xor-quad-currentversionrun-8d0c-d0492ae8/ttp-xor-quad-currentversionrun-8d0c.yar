rule TTP_XOR_QUAD_CurrentVersionRun_8d0c {
  strings:
    $key_8d0c = { de 63 [2] fa 6d [2] d1 41 [2] ff 63 [2] eb 78 [2] e4 62 [2] fa 7f [2] f8 7e [2] e3 78 [2] ff 7f [2] e3 50 }

  condition:
    any of them
}
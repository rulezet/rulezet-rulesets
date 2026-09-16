rule TTP_XOR_QUAD_CurrentVersionRun_8d3c {
  strings:
    $key_8d3c = { de 53 [2] fa 5d [2] d1 71 [2] ff 53 [2] eb 48 [2] e4 52 [2] fa 4f [2] f8 4e [2] e3 48 [2] ff 4f [2] e3 60 }

  condition:
    any of them
}
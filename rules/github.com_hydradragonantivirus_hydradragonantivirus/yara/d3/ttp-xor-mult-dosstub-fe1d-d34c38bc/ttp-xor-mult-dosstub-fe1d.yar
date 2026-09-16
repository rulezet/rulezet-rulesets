rule TTP_XOR_MULT_DOSStub_fe1d {
  strings:
    $key_fe1d = { aa 75 [2] de 6d [2] 99 6f [2] de 7e [2] 90 72 [2] 9c 78 [2] 8b 73 [2] 90 3d [2] ad }

  condition:
    any of them
}
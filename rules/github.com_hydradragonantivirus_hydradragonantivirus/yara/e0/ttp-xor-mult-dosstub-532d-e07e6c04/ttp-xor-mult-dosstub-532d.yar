rule TTP_XOR_MULT_DOSStub_532d {
  strings:
    $key_532d = { 07 45 [2] 73 5d [2] 34 5f [2] 73 4e [2] 3d 42 [2] 31 48 [2] 26 43 [2] 3d 0d [2] 00 }

  condition:
    any of them
}
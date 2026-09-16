rule TTP_XOR_MULT_DOSStub_006d {
  strings:
    $key_006d = { 54 05 [2] 20 1d [2] 67 1f [2] 20 0e [2] 6e 02 [2] 62 08 [2] 75 03 [2] 6e 4d [2] 53 }

  condition:
    any of them
}
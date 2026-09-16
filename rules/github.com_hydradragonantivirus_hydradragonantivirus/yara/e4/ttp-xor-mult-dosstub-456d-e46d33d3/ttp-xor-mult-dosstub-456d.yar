rule TTP_XOR_MULT_DOSStub_456d {
  strings:
    $key_456d = { 11 05 [2] 65 1d [2] 22 1f [2] 65 0e [2] 2b 02 [2] 27 08 [2] 30 03 [2] 2b 4d [2] 16 }

  condition:
    any of them
}
rule TTP_XOR_MULT_DOSStub_de6d {
  strings:
    $key_de6d = { 8a 05 [2] fe 1d [2] b9 1f [2] fe 0e [2] b0 02 [2] bc 08 [2] ab 03 [2] b0 4d [2] 8d }

  condition:
    any of them
}
rule TTP_XOR_MULT_DOSStub_de6c {
  strings:
    $key_de6c = { 8a 04 [2] fe 1c [2] b9 1e [2] fe 0f [2] b0 03 [2] bc 09 [2] ab 02 [2] b0 4c [2] 8d }

  condition:
    any of them
}
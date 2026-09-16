rule TTP_XOR_MULT_DOSStub_de2b {
  strings:
    $key_de2b = { 8a 43 [2] fe 5b [2] b9 59 [2] fe 48 [2] b0 44 [2] bc 4e [2] ab 45 [2] b0 0b [2] 8d }

  condition:
    any of them
}
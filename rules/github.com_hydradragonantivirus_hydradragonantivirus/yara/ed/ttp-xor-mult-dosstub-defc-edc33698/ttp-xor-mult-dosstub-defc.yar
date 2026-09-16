rule TTP_XOR_MULT_DOSStub_defc {
  strings:
    $key_defc = { 8a 94 [2] fe 8c [2] b9 8e [2] fe 9f [2] b0 93 [2] bc 99 [2] ab 92 [2] b0 dc [2] 8d }

  condition:
    any of them
}
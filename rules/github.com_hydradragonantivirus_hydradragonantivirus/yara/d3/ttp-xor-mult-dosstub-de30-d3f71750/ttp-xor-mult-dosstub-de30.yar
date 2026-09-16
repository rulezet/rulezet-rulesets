rule TTP_XOR_MULT_DOSStub_de30 {
  strings:
    $key_de30 = { 8a 58 [2] fe 40 [2] b9 42 [2] fe 53 [2] b0 5f [2] bc 55 [2] ab 5e [2] b0 10 [2] 8d }

  condition:
    any of them
}
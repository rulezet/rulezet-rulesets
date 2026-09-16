rule TTP_XOR_MULT_DOSStub_de67 {
  strings:
    $key_de67 = { 8a 0f [2] fe 17 [2] b9 15 [2] fe 04 [2] b0 08 [2] bc 02 [2] ab 09 [2] b0 47 [2] 8d }

  condition:
    any of them
}
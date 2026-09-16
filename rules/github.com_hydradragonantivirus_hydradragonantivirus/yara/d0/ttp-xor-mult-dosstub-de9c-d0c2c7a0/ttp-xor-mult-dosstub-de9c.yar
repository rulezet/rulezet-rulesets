rule TTP_XOR_MULT_DOSStub_de9c {
  strings:
    $key_de9c = { 8a f4 [2] fe ec [2] b9 ee [2] fe ff [2] b0 f3 [2] bc f9 [2] ab f2 [2] b0 bc [2] 8d }

  condition:
    any of them
}
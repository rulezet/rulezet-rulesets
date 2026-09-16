rule TTP_XOR_MULT_DOSStub_decc {
  strings:
    $key_decc = { 8a a4 [2] fe bc [2] b9 be [2] fe af [2] b0 a3 [2] bc a9 [2] ab a2 [2] b0 ec [2] 8d }

  condition:
    any of them
}
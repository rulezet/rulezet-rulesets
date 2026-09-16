rule TTP_XOR_MULT_DOSStub_de85 {
  strings:
    $key_de85 = { 8a ed [2] fe f5 [2] b9 f7 [2] fe e6 [2] b0 ea [2] bc e0 [2] ab eb [2] b0 a5 [2] 8d }

  condition:
    any of them
}
rule TTP_XOR_MULT_DOSStub_de82 {
  strings:
    $key_de82 = { 8a ea [2] fe f2 [2] b9 f0 [2] fe e1 [2] b0 ed [2] bc e7 [2] ab ec [2] b0 a2 [2] 8d }

  condition:
    any of them
}
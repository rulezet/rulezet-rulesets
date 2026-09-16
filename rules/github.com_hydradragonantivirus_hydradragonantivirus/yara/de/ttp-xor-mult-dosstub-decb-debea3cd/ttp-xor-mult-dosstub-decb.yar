rule TTP_XOR_MULT_DOSStub_decb {
  strings:
    $key_decb = { 8a a3 [2] fe bb [2] b9 b9 [2] fe a8 [2] b0 a4 [2] bc ae [2] ab a5 [2] b0 eb [2] 8d }

  condition:
    any of them
}
rule TTP_XOR_MULT_DOSStub_deab {
  strings:
    $key_deab = { 8a c3 [2] fe db [2] b9 d9 [2] fe c8 [2] b0 c4 [2] bc ce [2] ab c5 [2] b0 8b [2] 8d }

  condition:
    any of them
}
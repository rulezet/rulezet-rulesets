rule TTP_XOR_MULT_DOSStub_de86 {
  strings:
    $key_de86 = { 8a ee [2] fe f6 [2] b9 f4 [2] fe e5 [2] b0 e9 [2] bc e3 [2] ab e8 [2] b0 a6 [2] 8d }

  condition:
    any of them
}
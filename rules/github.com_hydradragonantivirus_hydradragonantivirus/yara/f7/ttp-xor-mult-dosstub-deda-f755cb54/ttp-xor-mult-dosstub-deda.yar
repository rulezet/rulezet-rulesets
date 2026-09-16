rule TTP_XOR_MULT_DOSStub_deda {
  strings:
    $key_deda = { 8a b2 [2] fe aa [2] b9 a8 [2] fe b9 [2] b0 b5 [2] bc bf [2] ab b4 [2] b0 fa [2] 8d }

  condition:
    any of them
}
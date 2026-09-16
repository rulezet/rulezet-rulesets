rule TTP_XOR_MULT_DOSStub_de95 {
  strings:
    $key_de95 = { 8a fd [2] fe e5 [2] b9 e7 [2] fe f6 [2] b0 fa [2] bc f0 [2] ab fb [2] b0 b5 [2] 8d }

  condition:
    any of them
}
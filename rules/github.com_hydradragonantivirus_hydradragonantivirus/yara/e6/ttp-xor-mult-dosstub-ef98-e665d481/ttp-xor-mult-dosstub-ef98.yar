rule TTP_XOR_MULT_DOSStub_ef98 {
  strings:
    $key_ef98 = { bb f0 [2] cf e8 [2] 88 ea [2] cf fb [2] 81 f7 [2] 8d fd [2] 9a f6 [2] 81 b8 [2] bc }

  condition:
    any of them
}
rule TTP_XOR_MULT_DOSStub_ef97 {
  strings:
    $key_ef97 = { bb ff [2] cf e7 [2] 88 e5 [2] cf f4 [2] 81 f8 [2] 8d f2 [2] 9a f9 [2] 81 b7 [2] bc }

  condition:
    any of them
}
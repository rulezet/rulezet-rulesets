rule TTP_XOR_MULT_DOSStub_6797 {
  strings:
    $key_6797 = { 33 ff [2] 47 e7 [2] 00 e5 [2] 47 f4 [2] 09 f8 [2] 05 f2 [2] 12 f9 [2] 09 b7 [2] 34 }

  condition:
    any of them
}
rule TTP_XOR_MULT_DOSStub_5797 {
  strings:
    $key_5797 = { 03 ff [2] 77 e7 [2] 30 e5 [2] 77 f4 [2] 39 f8 [2] 35 f2 [2] 22 f9 [2] 39 b7 [2] 04 }

  condition:
    any of them
}
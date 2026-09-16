rule TTP_XOR_MULT_DOSStub_2491 {
  strings:
    $key_2491 = { 70 f9 [2] 04 e1 [2] 43 e3 [2] 04 f2 [2] 4a fe [2] 46 f4 [2] 51 ff [2] 4a b1 [2] 77 }

  condition:
    any of them
}
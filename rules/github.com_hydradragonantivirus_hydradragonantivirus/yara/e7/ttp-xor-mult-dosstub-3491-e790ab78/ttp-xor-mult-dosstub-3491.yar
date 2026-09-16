rule TTP_XOR_MULT_DOSStub_3491 {
  strings:
    $key_3491 = { 60 f9 [2] 14 e1 [2] 53 e3 [2] 14 f2 [2] 5a fe [2] 56 f4 [2] 41 ff [2] 5a b1 [2] 67 }

  condition:
    any of them
}
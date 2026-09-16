rule TTP_XOR_MULT_DOSStub_238f {
  strings:
    $key_238f = { 77 e7 [2] 03 ff [2] 44 fd [2] 03 ec [2] 4d e0 [2] 41 ea [2] 56 e1 [2] 4d af [2] 70 }

  condition:
    any of them
}
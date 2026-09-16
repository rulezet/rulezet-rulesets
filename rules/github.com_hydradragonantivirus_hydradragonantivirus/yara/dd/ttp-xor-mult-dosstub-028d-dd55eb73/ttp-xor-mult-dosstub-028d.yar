rule TTP_XOR_MULT_DOSStub_028d {
  strings:
    $key_028d = { 56 e5 [2] 22 fd [2] 65 ff [2] 22 ee [2] 6c e2 [2] 60 e8 [2] 77 e3 [2] 6c ad [2] 51 }

  condition:
    any of them
}
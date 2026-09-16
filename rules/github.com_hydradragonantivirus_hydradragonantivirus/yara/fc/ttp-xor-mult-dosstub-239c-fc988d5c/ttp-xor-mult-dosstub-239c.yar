rule TTP_XOR_MULT_DOSStub_239c {
  strings:
    $key_239c = { 77 f4 [2] 03 ec [2] 44 ee [2] 03 ff [2] 4d f3 [2] 41 f9 [2] 56 f2 [2] 4d bc [2] 70 }

  condition:
    any of them
}
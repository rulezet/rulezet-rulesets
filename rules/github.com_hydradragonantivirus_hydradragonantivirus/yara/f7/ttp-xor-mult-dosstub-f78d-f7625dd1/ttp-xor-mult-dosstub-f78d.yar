rule TTP_XOR_MULT_DOSStub_f78d {
  strings:
    $key_f78d = { a3 e5 [2] d7 fd [2] 90 ff [2] d7 ee [2] 99 e2 [2] 95 e8 [2] 82 e3 [2] 99 ad [2] a4 }

  condition:
    any of them
}
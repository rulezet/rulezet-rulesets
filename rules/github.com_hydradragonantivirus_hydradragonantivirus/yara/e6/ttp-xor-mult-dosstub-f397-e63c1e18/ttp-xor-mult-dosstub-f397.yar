rule TTP_XOR_MULT_DOSStub_f397 {
  strings:
    $key_f397 = { a7 ff [2] d3 e7 [2] 94 e5 [2] d3 f4 [2] 9d f8 [2] 91 f2 [2] 86 f9 [2] 9d b7 [2] a0 }

  condition:
    any of them
}
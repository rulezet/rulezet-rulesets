rule TTP_XOR_MULT_DOSStub_f391 {
  strings:
    $key_f391 = { a7 f9 [2] d3 e1 [2] 94 e3 [2] d3 f2 [2] 9d fe [2] 91 f4 [2] 86 ff [2] 9d b1 [2] a0 }

  condition:
    any of them
}
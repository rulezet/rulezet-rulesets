rule TTP_XOR_MULT_DOSStub_f302 {
  strings:
    $key_f302 = { a7 6a [2] d3 72 [2] 94 70 [2] d3 61 [2] 9d 6d [2] 91 67 [2] 86 6c [2] 9d 22 [2] a0 }

  condition:
    any of them
}
rule TTP_XOR_MULT_DOSStub_f334 {
  strings:
    $key_f334 = { a7 5c [2] d3 44 [2] 94 46 [2] d3 57 [2] 9d 5b [2] 91 51 [2] 86 5a [2] 9d 14 [2] a0 }

  condition:
    any of them
}
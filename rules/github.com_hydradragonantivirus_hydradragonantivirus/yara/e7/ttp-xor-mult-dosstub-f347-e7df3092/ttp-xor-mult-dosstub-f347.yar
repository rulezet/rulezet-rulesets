rule TTP_XOR_MULT_DOSStub_f347 {
  strings:
    $key_f347 = { a7 2f [2] d3 37 [2] 94 35 [2] d3 24 [2] 9d 28 [2] 91 22 [2] 86 29 [2] 9d 67 [2] a0 }

  condition:
    any of them
}
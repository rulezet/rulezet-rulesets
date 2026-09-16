rule TTP_XOR_MULT_DOSStub_f346 {
  strings:
    $key_f346 = { a7 2e [2] d3 36 [2] 94 34 [2] d3 25 [2] 9d 29 [2] 91 23 [2] 86 28 [2] 9d 66 [2] a0 }

  condition:
    any of them
}
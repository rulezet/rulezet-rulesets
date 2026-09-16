rule TTP_XOR_MULT_DOSStub_f317 {
  strings:
    $key_f317 = { a7 7f [2] d3 67 [2] 94 65 [2] d3 74 [2] 9d 78 [2] 91 72 [2] 86 79 [2] 9d 37 [2] a0 }

  condition:
    any of them
}
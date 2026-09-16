rule TTP_XOR_MULT_DOSStub_f3f1 {
  strings:
    $key_f3f1 = { a7 99 [2] d3 81 [2] 94 83 [2] d3 92 [2] 9d 9e [2] 91 94 [2] 86 9f [2] 9d d1 [2] a0 }

  condition:
    any of them
}
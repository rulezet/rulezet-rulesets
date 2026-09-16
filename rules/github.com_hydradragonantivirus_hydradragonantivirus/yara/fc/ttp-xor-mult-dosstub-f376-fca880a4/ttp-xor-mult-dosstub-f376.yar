rule TTP_XOR_MULT_DOSStub_f376 {
  strings:
    $key_f376 = { a7 1e [2] d3 06 [2] 94 04 [2] d3 15 [2] 9d 19 [2] 91 13 [2] 86 18 [2] 9d 56 [2] a0 }

  condition:
    any of them
}
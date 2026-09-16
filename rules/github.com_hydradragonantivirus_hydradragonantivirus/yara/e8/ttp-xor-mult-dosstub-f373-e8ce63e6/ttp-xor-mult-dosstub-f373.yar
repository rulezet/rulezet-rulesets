rule TTP_XOR_MULT_DOSStub_f373 {
  strings:
    $key_f373 = { a7 1b [2] d3 03 [2] 94 01 [2] d3 10 [2] 9d 1c [2] 91 16 [2] 86 1d [2] 9d 53 [2] a0 }

  condition:
    any of them
}
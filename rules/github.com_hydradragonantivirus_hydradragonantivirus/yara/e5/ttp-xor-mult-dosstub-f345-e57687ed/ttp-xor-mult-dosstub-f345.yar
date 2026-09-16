rule TTP_XOR_MULT_DOSStub_f345 {
  strings:
    $key_f345 = { a7 2d [2] d3 35 [2] 94 37 [2] d3 26 [2] 9d 2a [2] 91 20 [2] 86 2b [2] 9d 65 [2] a0 }

  condition:
    any of them
}
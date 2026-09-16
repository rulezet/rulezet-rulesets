rule TTP_XOR_MULT_DOSStub_f3f8 {
  strings:
    $key_f3f8 = { a7 90 [2] d3 88 [2] 94 8a [2] d3 9b [2] 9d 97 [2] 91 9d [2] 86 96 [2] 9d d8 [2] a0 }

  condition:
    any of them
}
rule TTP_XOR_MULT_DOSStub_f3f5 {
  strings:
    $key_f3f5 = { a7 9d [2] d3 85 [2] 94 87 [2] d3 96 [2] 9d 9a [2] 91 90 [2] 86 9b [2] 9d d5 [2] a0 }

  condition:
    any of them
}
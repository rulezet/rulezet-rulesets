rule TTP_XOR_MULT_DOSStub_f3f9 {
  strings:
    $key_f3f9 = { a7 91 [2] d3 89 [2] 94 8b [2] d3 9a [2] 9d 96 [2] 91 9c [2] 86 97 [2] 9d d9 [2] a0 }

  condition:
    any of them
}
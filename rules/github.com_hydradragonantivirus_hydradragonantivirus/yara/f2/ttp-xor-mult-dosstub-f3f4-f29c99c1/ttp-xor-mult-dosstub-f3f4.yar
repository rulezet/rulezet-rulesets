rule TTP_XOR_MULT_DOSStub_f3f4 {
  strings:
    $key_f3f4 = { a7 9c [2] d3 84 [2] 94 86 [2] d3 97 [2] 9d 9b [2] 91 91 [2] 86 9a [2] 9d d4 [2] a0 }

  condition:
    any of them
}
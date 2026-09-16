rule TTP_XOR_MULT_DOSStub_f3f2 {
  strings:
    $key_f3f2 = { a7 9a [2] d3 82 [2] 94 80 [2] d3 91 [2] 9d 9d [2] 91 97 [2] 86 9c [2] 9d d2 [2] a0 }

  condition:
    any of them
}
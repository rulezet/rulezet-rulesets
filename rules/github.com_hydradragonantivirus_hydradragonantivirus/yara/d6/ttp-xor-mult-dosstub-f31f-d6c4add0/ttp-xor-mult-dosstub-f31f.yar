rule TTP_XOR_MULT_DOSStub_f31f {
  strings:
    $key_f31f = { a7 77 [2] d3 6f [2] 94 6d [2] d3 7c [2] 9d 70 [2] 91 7a [2] 86 71 [2] 9d 3f [2] a0 }

  condition:
    any of them
}
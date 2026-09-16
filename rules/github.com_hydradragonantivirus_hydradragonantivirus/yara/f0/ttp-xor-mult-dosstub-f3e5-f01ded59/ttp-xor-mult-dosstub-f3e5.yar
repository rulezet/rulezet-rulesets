rule TTP_XOR_MULT_DOSStub_f3e5 {
  strings:
    $key_f3e5 = { a7 8d [2] d3 95 [2] 94 97 [2] d3 86 [2] 9d 8a [2] 91 80 [2] 86 8b [2] 9d c5 [2] a0 }

  condition:
    any of them
}
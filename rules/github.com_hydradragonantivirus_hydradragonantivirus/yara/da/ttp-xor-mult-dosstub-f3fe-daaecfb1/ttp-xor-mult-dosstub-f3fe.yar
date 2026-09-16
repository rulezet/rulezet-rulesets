rule TTP_XOR_MULT_DOSStub_f3fe {
  strings:
    $key_f3fe = { a7 96 [2] d3 8e [2] 94 8c [2] d3 9d [2] 9d 91 [2] 91 9b [2] 86 90 [2] 9d de [2] a0 }

  condition:
    any of them
}
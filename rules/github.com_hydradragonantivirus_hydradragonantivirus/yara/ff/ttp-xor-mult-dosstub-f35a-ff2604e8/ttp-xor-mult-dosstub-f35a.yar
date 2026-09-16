rule TTP_XOR_MULT_DOSStub_f35a {
  strings:
    $key_f35a = { a7 32 [2] d3 2a [2] 94 28 [2] d3 39 [2] 9d 35 [2] 91 3f [2] 86 34 [2] 9d 7a [2] a0 }

  condition:
    any of them
}
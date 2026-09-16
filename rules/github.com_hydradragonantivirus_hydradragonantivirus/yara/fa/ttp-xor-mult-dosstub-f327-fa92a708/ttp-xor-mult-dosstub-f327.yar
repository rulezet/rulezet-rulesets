rule TTP_XOR_MULT_DOSStub_f327 {
  strings:
    $key_f327 = { a7 4f [2] d3 57 [2] 94 55 [2] d3 44 [2] 9d 48 [2] 91 42 [2] 86 49 [2] 9d 07 [2] a0 }

  condition:
    any of them
}
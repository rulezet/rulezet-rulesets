rule TTP_XOR_MULT_DOSStub_f331 {
  strings:
    $key_f331 = { a7 59 [2] d3 41 [2] 94 43 [2] d3 52 [2] 9d 5e [2] 91 54 [2] 86 5f [2] 9d 11 [2] a0 }

  condition:
    any of them
}
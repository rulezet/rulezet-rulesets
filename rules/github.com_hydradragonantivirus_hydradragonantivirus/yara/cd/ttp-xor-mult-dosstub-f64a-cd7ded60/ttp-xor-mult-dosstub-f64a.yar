rule TTP_XOR_MULT_DOSStub_f64a {
  strings:
    $key_f64a = { a2 22 [2] d6 3a [2] 91 38 [2] d6 29 [2] 98 25 [2] 94 2f [2] 83 24 [2] 98 6a [2] a5 }

  condition:
    any of them
}
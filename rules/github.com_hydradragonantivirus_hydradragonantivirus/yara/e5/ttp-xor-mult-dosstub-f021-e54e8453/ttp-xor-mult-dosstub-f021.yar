rule TTP_XOR_MULT_DOSStub_f021 {
  strings:
    $key_f021 = { a4 49 [2] d0 51 [2] 97 53 [2] d0 42 [2] 9e 4e [2] 92 44 [2] 85 4f [2] 9e 01 [2] a3 }

  condition:
    any of them
}
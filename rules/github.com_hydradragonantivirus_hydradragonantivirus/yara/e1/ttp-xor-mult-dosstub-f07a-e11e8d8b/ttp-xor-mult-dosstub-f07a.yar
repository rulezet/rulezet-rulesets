rule TTP_XOR_MULT_DOSStub_f07a {
  strings:
    $key_f07a = { a4 12 [2] d0 0a [2] 97 08 [2] d0 19 [2] 9e 15 [2] 92 1f [2] 85 14 [2] 9e 5a [2] a3 }

  condition:
    any of them
}
rule TTP_XOR_MULT_DOSStub_f72a {
  strings:
    $key_f72a = { a3 42 [2] d7 5a [2] 90 58 [2] d7 49 [2] 99 45 [2] 95 4f [2] 82 44 [2] 99 0a [2] a4 }

  condition:
    any of them
}
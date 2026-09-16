rule TTP_XOR_MULT_DOSStub_f07f {
  strings:
    $key_f07f = { a4 17 [2] d0 0f [2] 97 0d [2] d0 1c [2] 9e 10 [2] 92 1a [2] 85 11 [2] 9e 5f [2] a3 }

  condition:
    any of them
}
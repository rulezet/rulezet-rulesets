rule TTP_XOR_MULT_DOSStub_f73f {
  strings:
    $key_f73f = { a3 57 [2] d7 4f [2] 90 4d [2] d7 5c [2] 99 50 [2] 95 5a [2] 82 51 [2] 99 1f [2] a4 }

  condition:
    any of them
}
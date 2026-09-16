rule TTP_XOR_MULT_DOSStub_f75f {
  strings:
    $key_f75f = { a3 37 [2] d7 2f [2] 90 2d [2] d7 3c [2] 99 30 [2] 95 3a [2] 82 31 [2] 99 7f [2] a4 }

  condition:
    any of them
}
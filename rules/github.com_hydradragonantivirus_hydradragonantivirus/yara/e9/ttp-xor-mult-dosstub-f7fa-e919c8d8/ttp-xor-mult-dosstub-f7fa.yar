rule TTP_XOR_MULT_DOSStub_f7fa {
  strings:
    $key_f7fa = { a3 92 [2] d7 8a [2] 90 88 [2] d7 99 [2] 99 95 [2] 95 9f [2] 82 94 [2] 99 da [2] a4 }

  condition:
    any of them
}
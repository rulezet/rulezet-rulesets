rule TTP_XOR_MULT_DOSStub_f6fa {
  strings:
    $key_f6fa = { a2 92 [2] d6 8a [2] 91 88 [2] d6 99 [2] 98 95 [2] 94 9f [2] 83 94 [2] 98 da [2] a5 }

  condition:
    any of them
}
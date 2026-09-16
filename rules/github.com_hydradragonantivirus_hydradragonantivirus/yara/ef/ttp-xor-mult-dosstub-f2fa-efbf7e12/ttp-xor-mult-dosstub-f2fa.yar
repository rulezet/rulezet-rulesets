rule TTP_XOR_MULT_DOSStub_f2fa {
  strings:
    $key_f2fa = { a6 92 [2] d2 8a [2] 95 88 [2] d2 99 [2] 9c 95 [2] 90 9f [2] 87 94 [2] 9c da [2] a1 }

  condition:
    any of them
}
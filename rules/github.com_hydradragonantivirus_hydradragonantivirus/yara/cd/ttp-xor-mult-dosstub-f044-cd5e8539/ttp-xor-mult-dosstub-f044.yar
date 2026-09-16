rule TTP_XOR_MULT_DOSStub_f044 {
  strings:
    $key_f044 = { a4 2c [2] d0 34 [2] 97 36 [2] d0 27 [2] 9e 2b [2] 92 21 [2] 85 2a [2] 9e 64 [2] a3 }

  condition:
    any of them
}
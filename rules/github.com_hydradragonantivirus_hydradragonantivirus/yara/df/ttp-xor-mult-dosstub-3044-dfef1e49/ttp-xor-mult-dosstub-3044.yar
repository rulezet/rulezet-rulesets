rule TTP_XOR_MULT_DOSStub_3044 {
  strings:
    $key_3044 = { 64 2c [2] 10 34 [2] 57 36 [2] 10 27 [2] 5e 2b [2] 52 21 [2] 45 2a [2] 5e 64 [2] 63 }

  condition:
    any of them
}
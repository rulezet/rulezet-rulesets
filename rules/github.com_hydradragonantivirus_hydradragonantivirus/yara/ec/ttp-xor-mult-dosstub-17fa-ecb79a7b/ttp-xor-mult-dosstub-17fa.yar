rule TTP_XOR_MULT_DOSStub_17fa {
  strings:
    $key_17fa = { 43 92 [2] 37 8a [2] 70 88 [2] 37 99 [2] 79 95 [2] 75 9f [2] 62 94 [2] 79 da [2] 44 }

  condition:
    any of them
}
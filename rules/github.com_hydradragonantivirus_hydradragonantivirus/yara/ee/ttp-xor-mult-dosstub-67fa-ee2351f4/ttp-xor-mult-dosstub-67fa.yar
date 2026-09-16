rule TTP_XOR_MULT_DOSStub_67fa {
  strings:
    $key_67fa = { 33 92 [2] 47 8a [2] 00 88 [2] 47 99 [2] 09 95 [2] 05 9f [2] 12 94 [2] 09 da [2] 34 }

  condition:
    any of them
}
rule TTP_XOR_MULT_DOSStub_66fa {
  strings:
    $key_66fa = { 32 92 [2] 46 8a [2] 01 88 [2] 46 99 [2] 08 95 [2] 04 9f [2] 13 94 [2] 08 da [2] 35 }

  condition:
    any of them
}
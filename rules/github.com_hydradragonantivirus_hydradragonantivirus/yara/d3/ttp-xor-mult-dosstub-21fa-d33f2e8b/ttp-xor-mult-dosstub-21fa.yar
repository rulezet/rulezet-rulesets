rule TTP_XOR_MULT_DOSStub_21fa {
  strings:
    $key_21fa = { 75 92 [2] 01 8a [2] 46 88 [2] 01 99 [2] 4f 95 [2] 43 9f [2] 54 94 [2] 4f da [2] 72 }

  condition:
    any of them
}
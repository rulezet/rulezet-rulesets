rule TTP_XOR_MULT_DOSStub_18fa {
  strings:
    $key_18fa = { 4c 92 [2] 38 8a [2] 7f 88 [2] 38 99 [2] 76 95 [2] 7a 9f [2] 6d 94 [2] 76 da [2] 4b }

  condition:
    any of them
}
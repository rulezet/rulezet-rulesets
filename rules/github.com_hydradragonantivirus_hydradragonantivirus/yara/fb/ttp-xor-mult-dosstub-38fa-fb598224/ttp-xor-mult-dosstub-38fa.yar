rule TTP_XOR_MULT_DOSStub_38fa {
  strings:
    $key_38fa = { 6c 92 [2] 18 8a [2] 5f 88 [2] 18 99 [2] 56 95 [2] 5a 9f [2] 4d 94 [2] 56 da [2] 6b }

  condition:
    any of them
}
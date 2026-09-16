rule TTP_XOR_MULT_DOSStub_08fa {
  strings:
    $key_08fa = { 5c 92 [2] 28 8a [2] 6f 88 [2] 28 99 [2] 66 95 [2] 6a 9f [2] 7d 94 [2] 66 da [2] 5b }

  condition:
    any of them
}
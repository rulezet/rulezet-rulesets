rule TTP_XOR_MULT_DOSStub_68fa {
  strings:
    $key_68fa = { 3c 92 [2] 48 8a [2] 0f 88 [2] 48 99 [2] 06 95 [2] 0a 9f [2] 1d 94 [2] 06 da [2] 3b }

  condition:
    any of them
}
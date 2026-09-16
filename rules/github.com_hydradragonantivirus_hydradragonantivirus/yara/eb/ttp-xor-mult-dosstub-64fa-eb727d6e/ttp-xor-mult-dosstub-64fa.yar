rule TTP_XOR_MULT_DOSStub_64fa {
  strings:
    $key_64fa = { 30 92 [2] 44 8a [2] 03 88 [2] 44 99 [2] 0a 95 [2] 06 9f [2] 11 94 [2] 0a da [2] 37 }

  condition:
    any of them
}
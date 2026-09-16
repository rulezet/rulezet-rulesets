rule TTP_XOR_MULT_DOSStub_24fa {
  strings:
    $key_24fa = { 70 92 [2] 04 8a [2] 43 88 [2] 04 99 [2] 4a 95 [2] 46 9f [2] 51 94 [2] 4a da [2] 77 }

  condition:
    any of them
}
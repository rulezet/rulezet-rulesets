rule TTP_XOR_MULT_DOSStub_7ae5 {
  strings:
    $key_7ae5 = { 2e 8d [2] 5a 95 [2] 1d 97 [2] 5a 86 [2] 14 8a [2] 18 80 [2] 0f 8b [2] 14 c5 [2] 29 }

  condition:
    any of them
}
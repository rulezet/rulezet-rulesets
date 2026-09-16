rule TTP_XOR_MULT_DOSStub_7a78 {
  strings:
    $key_7a78 = { 2e 10 [2] 5a 08 [2] 1d 0a [2] 5a 1b [2] 14 17 [2] 18 1d [2] 0f 16 [2] 14 58 [2] 29 }

  condition:
    any of them
}
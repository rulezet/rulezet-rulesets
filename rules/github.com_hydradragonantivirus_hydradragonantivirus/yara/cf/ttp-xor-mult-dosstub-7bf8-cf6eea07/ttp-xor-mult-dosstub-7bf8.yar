rule TTP_XOR_MULT_DOSStub_7bf8 {
  strings:
    $key_7bf8 = { 2f 90 [2] 5b 88 [2] 1c 8a [2] 5b 9b [2] 15 97 [2] 19 9d [2] 0e 96 [2] 15 d8 [2] 28 }

  condition:
    any of them
}
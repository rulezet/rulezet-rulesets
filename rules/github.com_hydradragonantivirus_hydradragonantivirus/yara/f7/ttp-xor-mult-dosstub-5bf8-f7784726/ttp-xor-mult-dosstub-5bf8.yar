rule TTP_XOR_MULT_DOSStub_5bf8 {
  strings:
    $key_5bf8 = { 0f 90 [2] 7b 88 [2] 3c 8a [2] 7b 9b [2] 35 97 [2] 39 9d [2] 2e 96 [2] 35 d8 [2] 08 }

  condition:
    any of them
}
rule TTP_XOR_MULT_DOSStub_5b65 {
  strings:
    $key_5b65 = { 0f 0d [2] 7b 15 [2] 3c 17 [2] 7b 06 [2] 35 0a [2] 39 00 [2] 2e 0b [2] 35 45 [2] 08 }

  condition:
    any of them
}
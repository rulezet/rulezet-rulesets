rule TTP_XOR_MULT_DOSStub_5b68 {
  strings:
    $key_5b68 = { 0f 00 [2] 7b 18 [2] 3c 1a [2] 7b 0b [2] 35 07 [2] 39 0d [2] 2e 06 [2] 35 48 [2] 08 }

  condition:
    any of them
}
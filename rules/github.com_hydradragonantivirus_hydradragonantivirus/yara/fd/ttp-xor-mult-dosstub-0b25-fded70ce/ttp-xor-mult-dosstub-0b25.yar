rule TTP_XOR_MULT_DOSStub_0b25 {
  strings:
    $key_0b25 = { 5f 4d [2] 2b 55 [2] 6c 57 [2] 2b 46 [2] 65 4a [2] 69 40 [2] 7e 4b [2] 65 05 [2] 58 }

  condition:
    any of them
}
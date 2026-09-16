rule TTP_XOR_MULT_DOSStub_4b34 {
  strings:
    $key_4b34 = { 1f 5c [2] 6b 44 [2] 2c 46 [2] 6b 57 [2] 25 5b [2] 29 51 [2] 3e 5a [2] 25 14 [2] 18 }

  condition:
    any of them
}
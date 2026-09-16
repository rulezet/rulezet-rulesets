rule TTP_XOR_MULT_DOSStub_4534 {
  strings:
    $key_4534 = { 11 5c [2] 65 44 [2] 22 46 [2] 65 57 [2] 2b 5b [2] 27 51 [2] 30 5a [2] 2b 14 [2] 16 }

  condition:
    any of them
}
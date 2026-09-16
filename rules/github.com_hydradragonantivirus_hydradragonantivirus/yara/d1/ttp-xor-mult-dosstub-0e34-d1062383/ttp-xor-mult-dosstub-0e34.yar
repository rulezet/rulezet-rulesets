rule TTP_XOR_MULT_DOSStub_0e34 {
  strings:
    $key_0e34 = { 5a 5c [2] 2e 44 [2] 69 46 [2] 2e 57 [2] 60 5b [2] 6c 51 [2] 7b 5a [2] 60 14 [2] 5d }

  condition:
    any of them
}
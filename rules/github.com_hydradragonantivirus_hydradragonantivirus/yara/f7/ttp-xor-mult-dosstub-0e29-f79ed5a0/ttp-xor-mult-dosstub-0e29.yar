rule TTP_XOR_MULT_DOSStub_0e29 {
  strings:
    $key_0e29 = { 5a 41 [2] 2e 59 [2] 69 5b [2] 2e 4a [2] 60 46 [2] 6c 4c [2] 7b 47 [2] 60 09 [2] 5d }

  condition:
    any of them
}
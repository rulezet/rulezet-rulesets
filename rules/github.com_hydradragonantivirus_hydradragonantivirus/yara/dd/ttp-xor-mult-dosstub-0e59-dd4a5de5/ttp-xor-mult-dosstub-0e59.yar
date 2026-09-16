rule TTP_XOR_MULT_DOSStub_0e59 {
  strings:
    $key_0e59 = { 5a 31 [2] 2e 29 [2] 69 2b [2] 2e 3a [2] 60 36 [2] 6c 3c [2] 7b 37 [2] 60 79 [2] 5d }

  condition:
    any of them
}
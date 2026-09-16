rule TTP_XOR_MULT_DOSStub_5059 {
  strings:
    $key_5059 = { 04 31 [2] 70 29 [2] 37 2b [2] 70 3a [2] 3e 36 [2] 32 3c [2] 25 37 [2] 3e 79 [2] 03 }

  condition:
    any of them
}
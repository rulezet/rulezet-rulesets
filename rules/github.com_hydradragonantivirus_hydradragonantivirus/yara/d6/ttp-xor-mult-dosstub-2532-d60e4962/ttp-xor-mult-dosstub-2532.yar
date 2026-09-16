rule TTP_XOR_MULT_DOSStub_2532 {
  strings:
    $key_2532 = { 71 5a [2] 05 42 [2] 42 40 [2] 05 51 [2] 4b 5d [2] 47 57 [2] 50 5c [2] 4b 12 [2] 76 }

  condition:
    any of them
}
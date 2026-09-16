rule TTP_XOR_MULT_DOSStub_2535 {
  strings:
    $key_2535 = { 71 5d [2] 05 45 [2] 42 47 [2] 05 56 [2] 4b 5a [2] 47 50 [2] 50 5b [2] 4b 15 [2] 76 }

  condition:
    any of them
}
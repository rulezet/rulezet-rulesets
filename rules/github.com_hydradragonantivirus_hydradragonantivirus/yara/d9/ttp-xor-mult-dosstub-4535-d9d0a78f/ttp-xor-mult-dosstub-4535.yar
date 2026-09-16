rule TTP_XOR_MULT_DOSStub_4535 {
  strings:
    $key_4535 = { 11 5d [2] 65 45 [2] 22 47 [2] 65 56 [2] 2b 5a [2] 27 50 [2] 30 5b [2] 2b 15 [2] 16 }

  condition:
    any of them
}
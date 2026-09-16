rule TTP_XOR_MULT_DOSStub_5d35 {
  strings:
    $key_5d35 = { 09 5d [2] 7d 45 [2] 3a 47 [2] 7d 56 [2] 33 5a [2] 3f 50 [2] 28 5b [2] 33 15 [2] 0e }

  condition:
    any of them
}
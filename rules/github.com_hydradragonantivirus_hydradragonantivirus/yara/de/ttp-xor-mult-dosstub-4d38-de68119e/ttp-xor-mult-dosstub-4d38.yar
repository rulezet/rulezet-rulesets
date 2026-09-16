rule TTP_XOR_MULT_DOSStub_4d38 {
  strings:
    $key_4d38 = { 19 50 [2] 6d 48 [2] 2a 4a [2] 6d 5b [2] 23 57 [2] 2f 5d [2] 38 56 [2] 23 18 [2] 1e }

  condition:
    any of them
}
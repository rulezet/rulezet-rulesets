rule TTP_XOR_MULT_DOSStub_3905 {
  strings:
    $key_3905 = { 6d 6d [2] 19 75 [2] 5e 77 [2] 19 66 [2] 57 6a [2] 5b 60 [2] 4c 6b [2] 57 25 [2] 6a }

  condition:
    any of them
}
rule TTP_XOR_MULT_DOSStub_1905 {
  strings:
    $key_1905 = { 4d 6d [2] 39 75 [2] 7e 77 [2] 39 66 [2] 77 6a [2] 7b 60 [2] 6c 6b [2] 77 25 [2] 4a }

  condition:
    any of them
}
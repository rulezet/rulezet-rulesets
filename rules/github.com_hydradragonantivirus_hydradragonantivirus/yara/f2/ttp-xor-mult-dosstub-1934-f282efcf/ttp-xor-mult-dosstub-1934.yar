rule TTP_XOR_MULT_DOSStub_1934 {
  strings:
    $key_1934 = { 4d 5c [2] 39 44 [2] 7e 46 [2] 39 57 [2] 77 5b [2] 7b 51 [2] 6c 5a [2] 77 14 [2] 4a }

  condition:
    any of them
}
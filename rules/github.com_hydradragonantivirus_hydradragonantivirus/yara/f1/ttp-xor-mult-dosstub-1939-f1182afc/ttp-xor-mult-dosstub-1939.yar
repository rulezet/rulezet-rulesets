rule TTP_XOR_MULT_DOSStub_1939 {
  strings:
    $key_1939 = { 4d 51 [2] 39 49 [2] 7e 4b [2] 39 5a [2] 77 56 [2] 7b 5c [2] 6c 57 [2] 77 19 [2] 4a }

  condition:
    any of them
}
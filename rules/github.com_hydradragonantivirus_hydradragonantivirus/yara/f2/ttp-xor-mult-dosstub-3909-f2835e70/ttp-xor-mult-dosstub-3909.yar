rule TTP_XOR_MULT_DOSStub_3909 {
  strings:
    $key_3909 = { 6d 61 [2] 19 79 [2] 5e 7b [2] 19 6a [2] 57 66 [2] 5b 6c [2] 4c 67 [2] 57 29 [2] 6a }

  condition:
    any of them
}
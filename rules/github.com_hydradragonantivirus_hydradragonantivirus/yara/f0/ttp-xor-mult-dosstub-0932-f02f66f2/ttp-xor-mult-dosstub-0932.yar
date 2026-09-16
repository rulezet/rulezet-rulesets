rule TTP_XOR_MULT_DOSStub_0932 {
  strings:
    $key_0932 = { 5d 5a [2] 29 42 [2] 6e 40 [2] 29 51 [2] 67 5d [2] 6b 57 [2] 7c 5c [2] 67 12 [2] 5a }

  condition:
    any of them
}
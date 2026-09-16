rule TTP_XOR_MULT_DOSStub_0933 {
  strings:
    $key_0933 = { 5d 5b [2] 29 43 [2] 6e 41 [2] 29 50 [2] 67 5c [2] 6b 56 [2] 7c 5d [2] 67 13 [2] 5a }

  condition:
    any of them
}
rule TTP_XOR_MULT_DOSStub_b739 {
  strings:
    $key_b739 = { e3 51 [2] 97 49 [2] d0 4b [2] 97 5a [2] d9 56 [2] d5 5c [2] c2 57 [2] d9 19 [2] e4 }

  condition:
    any of them
}
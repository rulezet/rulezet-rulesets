rule TTP_XOR_MULT_DOSStub_b709 {
  strings:
    $key_b709 = { e3 61 [2] 97 79 [2] d0 7b [2] 97 6a [2] d9 66 [2] d5 6c [2] c2 67 [2] d9 29 [2] e4 }

  condition:
    any of them
}
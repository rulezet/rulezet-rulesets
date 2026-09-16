rule TTP_XOR_MULT_DOSStub_b708 {
  strings:
    $key_b708 = { e3 60 [2] 97 78 [2] d0 7a [2] 97 6b [2] d9 67 [2] d5 6d [2] c2 66 [2] d9 28 [2] e4 }

  condition:
    any of them
}
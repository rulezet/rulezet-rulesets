rule TTP_XOR_MULT_DOSStub_b762 {
  strings:
    $key_b762 = { e3 0a [2] 97 12 [2] d0 10 [2] 97 01 [2] d9 0d [2] d5 07 [2] c2 0c [2] d9 42 [2] e4 }

  condition:
    any of them
}
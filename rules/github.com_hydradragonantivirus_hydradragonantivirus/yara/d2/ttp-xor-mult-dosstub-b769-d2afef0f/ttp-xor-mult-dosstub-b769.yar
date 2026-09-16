rule TTP_XOR_MULT_DOSStub_b769 {
  strings:
    $key_b769 = { e3 01 [2] 97 19 [2] d0 1b [2] 97 0a [2] d9 06 [2] d5 0c [2] c2 07 [2] d9 49 [2] e4 }

  condition:
    any of them
}
rule TTP_XOR_MULT_DOSStub_b674 {
  strings:
    $key_b674 = { e2 1c [2] 96 04 [2] d1 06 [2] 96 17 [2] d8 1b [2] d4 11 [2] c3 1a [2] d8 54 [2] e5 }

  condition:
    any of them
}
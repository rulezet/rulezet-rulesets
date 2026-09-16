rule TTP_XOR_MULT_DOSStub_b673 {
  strings:
    $key_b673 = { e2 1b [2] 96 03 [2] d1 01 [2] 96 10 [2] d8 1c [2] d4 16 [2] c3 1d [2] d8 53 [2] e5 }

  condition:
    any of them
}
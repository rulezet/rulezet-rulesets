rule TTP_XOR_MULT_DOSStub_a709 {
  strings:
    $key_a709 = { f3 61 [2] 87 79 [2] c0 7b [2] 87 6a [2] c9 66 [2] c5 6c [2] d2 67 [2] c9 29 [2] f4 }

  condition:
    any of them
}
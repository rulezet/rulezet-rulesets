rule TTP_XOR_MULT_DOSStub_8319 {
  strings:
    $key_8319 = { d7 71 [2] a3 69 [2] e4 6b [2] a3 7a [2] ed 76 [2] e1 7c [2] f6 77 [2] ed 39 [2] d0 }

  condition:
    any of them
}
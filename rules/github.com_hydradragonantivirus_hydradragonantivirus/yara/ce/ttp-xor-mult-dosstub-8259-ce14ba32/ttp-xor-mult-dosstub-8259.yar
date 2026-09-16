rule TTP_XOR_MULT_DOSStub_8259 {
  strings:
    $key_8259 = { d6 31 [2] a2 29 [2] e5 2b [2] a2 3a [2] ec 36 [2] e0 3c [2] f7 37 [2] ec 79 [2] d1 }

  condition:
    any of them
}
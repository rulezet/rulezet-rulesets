rule TTP_XOR_MULT_DOSStub_831e {
  strings:
    $key_831e = { d7 76 [2] a3 6e [2] e4 6c [2] a3 7d [2] ed 71 [2] e1 7b [2] f6 70 [2] ed 3e [2] d0 }

  condition:
    any of them
}
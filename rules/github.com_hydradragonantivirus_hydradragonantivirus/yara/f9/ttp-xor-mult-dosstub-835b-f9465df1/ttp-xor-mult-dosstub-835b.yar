rule TTP_XOR_MULT_DOSStub_835b {
  strings:
    $key_835b = { d7 33 [2] a3 2b [2] e4 29 [2] a3 38 [2] ed 34 [2] e1 3e [2] f6 35 [2] ed 7b [2] d0 }

  condition:
    any of them
}
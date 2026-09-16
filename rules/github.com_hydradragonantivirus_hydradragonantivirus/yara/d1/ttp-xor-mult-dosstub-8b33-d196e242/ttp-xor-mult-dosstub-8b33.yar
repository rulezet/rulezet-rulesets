rule TTP_XOR_MULT_DOSStub_8b33 {
  strings:
    $key_8b33 = { df 5b [2] ab 43 [2] ec 41 [2] ab 50 [2] e5 5c [2] e9 56 [2] fe 5d [2] e5 13 [2] d8 }

  condition:
    any of them
}
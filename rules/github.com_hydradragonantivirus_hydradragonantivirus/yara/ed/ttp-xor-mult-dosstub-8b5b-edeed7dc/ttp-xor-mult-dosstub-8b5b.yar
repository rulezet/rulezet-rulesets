rule TTP_XOR_MULT_DOSStub_8b5b {
  strings:
    $key_8b5b = { df 33 [2] ab 2b [2] ec 29 [2] ab 38 [2] e5 34 [2] e9 3e [2] fe 35 [2] e5 7b [2] d8 }

  condition:
    any of them
}
rule TTP_XOR_MULT_DOSStub_8b46 {
  strings:
    $key_8b46 = { df 2e [2] ab 36 [2] ec 34 [2] ab 25 [2] e5 29 [2] e9 23 [2] fe 28 [2] e5 66 [2] d8 }

  condition:
    any of them
}
rule TTP_XOR_MULT_DOSStub_8b40 {
  strings:
    $key_8b40 = { df 28 [2] ab 30 [2] ec 32 [2] ab 23 [2] e5 2f [2] e9 25 [2] fe 2e [2] e5 60 [2] d8 }

  condition:
    any of them
}
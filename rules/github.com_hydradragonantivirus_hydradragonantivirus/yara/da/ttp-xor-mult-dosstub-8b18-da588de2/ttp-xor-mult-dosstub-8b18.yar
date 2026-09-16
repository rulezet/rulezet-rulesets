rule TTP_XOR_MULT_DOSStub_8b18 {
  strings:
    $key_8b18 = { df 70 [2] ab 68 [2] ec 6a [2] ab 7b [2] e5 77 [2] e9 7d [2] fe 76 [2] e5 38 [2] d8 }

  condition:
    any of them
}
rule TTP_XOR_MULT_DOSStub_8b17 {
  strings:
    $key_8b17 = { df 7f [2] ab 67 [2] ec 65 [2] ab 74 [2] e5 78 [2] e9 72 [2] fe 79 [2] e5 37 [2] d8 }

  condition:
    any of them
}
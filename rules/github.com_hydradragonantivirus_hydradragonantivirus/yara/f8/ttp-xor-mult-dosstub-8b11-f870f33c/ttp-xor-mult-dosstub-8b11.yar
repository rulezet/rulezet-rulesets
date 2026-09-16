rule TTP_XOR_MULT_DOSStub_8b11 {
  strings:
    $key_8b11 = { df 79 [2] ab 61 [2] ec 63 [2] ab 72 [2] e5 7e [2] e9 74 [2] fe 7f [2] e5 31 [2] d8 }

  condition:
    any of them
}
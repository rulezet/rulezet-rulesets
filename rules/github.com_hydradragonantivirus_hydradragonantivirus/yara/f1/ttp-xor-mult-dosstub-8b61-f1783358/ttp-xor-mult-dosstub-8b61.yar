rule TTP_XOR_MULT_DOSStub_8b61 {
  strings:
    $key_8b61 = { df 09 [2] ab 11 [2] ec 13 [2] ab 02 [2] e5 0e [2] e9 04 [2] fe 0f [2] e5 41 [2] d8 }

  condition:
    any of them
}
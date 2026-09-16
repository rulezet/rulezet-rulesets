rule TTP_XOR_MULT_DOSStub_8b7b {
  strings:
    $key_8b7b = { df 13 [2] ab 0b [2] ec 09 [2] ab 18 [2] e5 14 [2] e9 1e [2] fe 15 [2] e5 5b [2] d8 }

  condition:
    any of them
}
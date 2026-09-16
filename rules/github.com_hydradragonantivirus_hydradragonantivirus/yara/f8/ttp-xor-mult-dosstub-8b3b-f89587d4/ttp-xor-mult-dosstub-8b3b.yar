rule TTP_XOR_MULT_DOSStub_8b3b {
  strings:
    $key_8b3b = { df 53 [2] ab 4b [2] ec 49 [2] ab 58 [2] e5 54 [2] e9 5e [2] fe 55 [2] e5 1b [2] d8 }

  condition:
    any of them
}
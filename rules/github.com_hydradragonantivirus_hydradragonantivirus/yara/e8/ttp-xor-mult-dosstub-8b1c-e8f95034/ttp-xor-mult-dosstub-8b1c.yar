rule TTP_XOR_MULT_DOSStub_8b1c {
  strings:
    $key_8b1c = { df 74 [2] ab 6c [2] ec 6e [2] ab 7f [2] e5 73 [2] e9 79 [2] fe 72 [2] e5 3c [2] d8 }

  condition:
    any of them
}
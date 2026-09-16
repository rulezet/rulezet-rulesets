rule TTP_XOR_MULT_DOSStub_8bec {
  strings:
    $key_8bec = { df 84 [2] ab 9c [2] ec 9e [2] ab 8f [2] e5 83 [2] e9 89 [2] fe 82 [2] e5 cc [2] d8 }

  condition:
    any of them
}
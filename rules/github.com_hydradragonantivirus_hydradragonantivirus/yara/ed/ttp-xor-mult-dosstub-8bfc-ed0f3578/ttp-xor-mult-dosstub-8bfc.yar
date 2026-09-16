rule TTP_XOR_MULT_DOSStub_8bfc {
  strings:
    $key_8bfc = { df 94 [2] ab 8c [2] ec 8e [2] ab 9f [2] e5 93 [2] e9 99 [2] fe 92 [2] e5 dc [2] d8 }

  condition:
    any of them
}
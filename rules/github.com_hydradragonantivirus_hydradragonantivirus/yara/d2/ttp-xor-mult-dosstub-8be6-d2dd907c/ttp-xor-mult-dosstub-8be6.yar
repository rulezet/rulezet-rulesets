rule TTP_XOR_MULT_DOSStub_8be6 {
  strings:
    $key_8be6 = { df 8e [2] ab 96 [2] ec 94 [2] ab 85 [2] e5 89 [2] e9 83 [2] fe 88 [2] e5 c6 [2] d8 }

  condition:
    any of them
}
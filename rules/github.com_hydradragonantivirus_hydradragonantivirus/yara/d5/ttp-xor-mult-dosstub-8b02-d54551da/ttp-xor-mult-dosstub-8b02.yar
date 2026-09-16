rule TTP_XOR_MULT_DOSStub_8b02 {
  strings:
    $key_8b02 = { df 6a [2] ab 72 [2] ec 70 [2] ab 61 [2] e5 6d [2] e9 67 [2] fe 6c [2] e5 22 [2] d8 }

  condition:
    any of them
}
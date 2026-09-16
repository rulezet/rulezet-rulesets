rule TTP_XOR_MULT_DOSStub_8bf8 {
  strings:
    $key_8bf8 = { df 90 [2] ab 88 [2] ec 8a [2] ab 9b [2] e5 97 [2] e9 9d [2] fe 96 [2] e5 d8 [2] d8 }

  condition:
    any of them
}
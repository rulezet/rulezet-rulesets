rule TTP_XOR_MULT_DOSStub_8bf4 {
  strings:
    $key_8bf4 = { df 9c [2] ab 84 [2] ec 86 [2] ab 97 [2] e5 9b [2] e9 91 [2] fe 9a [2] e5 d4 [2] d8 }

  condition:
    any of them
}
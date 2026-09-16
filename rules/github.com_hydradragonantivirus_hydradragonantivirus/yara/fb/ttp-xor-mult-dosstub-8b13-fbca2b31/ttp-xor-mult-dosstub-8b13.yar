rule TTP_XOR_MULT_DOSStub_8b13 {
  strings:
    $key_8b13 = { df 7b [2] ab 63 [2] ec 61 [2] ab 70 [2] e5 7c [2] e9 76 [2] fe 7d [2] e5 33 [2] d8 }

  condition:
    any of them
}
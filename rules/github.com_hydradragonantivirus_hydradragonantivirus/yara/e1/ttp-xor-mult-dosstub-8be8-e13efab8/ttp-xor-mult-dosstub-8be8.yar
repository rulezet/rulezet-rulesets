rule TTP_XOR_MULT_DOSStub_8be8 {
  strings:
    $key_8be8 = { df 80 [2] ab 98 [2] ec 9a [2] ab 8b [2] e5 87 [2] e9 8d [2] fe 86 [2] e5 c8 [2] d8 }

  condition:
    any of them
}
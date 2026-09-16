rule TTP_XOR_MULT_DOSStub_8b32 {
  strings:
    $key_8b32 = { df 5a [2] ab 42 [2] ec 40 [2] ab 51 [2] e5 5d [2] e9 57 [2] fe 5c [2] e5 12 [2] d8 }

  condition:
    any of them
}
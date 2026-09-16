rule TTP_XOR_MULT_DOSStub_8b07 {
  strings:
    $key_8b07 = { df 6f [2] ab 77 [2] ec 75 [2] ab 64 [2] e5 68 [2] e9 62 [2] fe 69 [2] e5 27 [2] d8 }

  condition:
    any of them
}
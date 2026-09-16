rule TTP_XOR_MULT_DOSStub_8b6d {
  strings:
    $key_8b6d = { df 05 [2] ab 1d [2] ec 1f [2] ab 0e [2] e5 02 [2] e9 08 [2] fe 03 [2] e5 4d [2] d8 }

  condition:
    any of them
}
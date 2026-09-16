rule TTP_XOR_MULT_DOSStub_8b1d {
  strings:
    $key_8b1d = { df 75 [2] ab 6d [2] ec 6f [2] ab 7e [2] e5 72 [2] e9 78 [2] fe 73 [2] e5 3d [2] d8 }

  condition:
    any of them
}
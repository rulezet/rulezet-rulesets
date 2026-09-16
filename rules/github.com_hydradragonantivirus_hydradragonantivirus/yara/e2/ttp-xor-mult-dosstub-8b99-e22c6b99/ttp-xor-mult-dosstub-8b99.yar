rule TTP_XOR_MULT_DOSStub_8b99 {
  strings:
    $key_8b99 = { df f1 [2] ab e9 [2] ec eb [2] ab fa [2] e5 f6 [2] e9 fc [2] fe f7 [2] e5 b9 [2] d8 }

  condition:
    any of them
}
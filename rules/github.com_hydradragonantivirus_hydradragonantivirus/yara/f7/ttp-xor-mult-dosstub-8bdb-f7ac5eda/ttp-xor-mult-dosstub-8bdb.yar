rule TTP_XOR_MULT_DOSStub_8bdb {
  strings:
    $key_8bdb = { df b3 [2] ab ab [2] ec a9 [2] ab b8 [2] e5 b4 [2] e9 be [2] fe b5 [2] e5 fb [2] d8 }

  condition:
    any of them
}
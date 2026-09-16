rule TTP_XOR_MULT_DOSStub_516e {
  strings:
    $key_516e = { 05 06 [2] 71 1e [2] 36 1c [2] 71 0d [2] 3f 01 [2] 33 0b [2] 24 00 [2] 3f 4e [2] 02 }

  condition:
    any of them
}
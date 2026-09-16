rule TTP_XOR_MULT_DOSStub_46fe {
  strings:
    $key_46fe = { 12 96 [2] 66 8e [2] 21 8c [2] 66 9d [2] 28 91 [2] 24 9b [2] 33 90 [2] 28 de [2] 15 }

  condition:
    any of them
}
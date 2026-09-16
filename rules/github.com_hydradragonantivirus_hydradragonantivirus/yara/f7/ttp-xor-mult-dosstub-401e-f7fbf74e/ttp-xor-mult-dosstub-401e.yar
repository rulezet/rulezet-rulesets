rule TTP_XOR_MULT_DOSStub_401e {
  strings:
    $key_401e = { 14 76 [2] 60 6e [2] 27 6c [2] 60 7d [2] 2e 71 [2] 22 7b [2] 35 70 [2] 2e 3e [2] 13 }

  condition:
    any of them
}
rule TTP_XOR_MULT_DOSStub_540e {
  strings:
    $key_540e = { 00 66 [2] 74 7e [2] 33 7c [2] 74 6d [2] 3a 61 [2] 36 6b [2] 21 60 [2] 3a 2e [2] 07 }

  condition:
    any of them
}
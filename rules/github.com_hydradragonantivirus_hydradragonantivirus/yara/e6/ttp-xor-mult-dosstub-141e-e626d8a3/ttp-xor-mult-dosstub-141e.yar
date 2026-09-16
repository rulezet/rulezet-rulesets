rule TTP_XOR_MULT_DOSStub_141e {
  strings:
    $key_141e = { 40 76 [2] 34 6e [2] 73 6c [2] 34 7d [2] 7a 71 [2] 76 7b [2] 61 70 [2] 7a 3e [2] 47 }

  condition:
    any of them
}
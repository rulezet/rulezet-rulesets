rule TTP_XOR_MULT_DOSStub_223e {
  strings:
    $key_223e = { 76 56 [2] 02 4e [2] 45 4c [2] 02 5d [2] 4c 51 [2] 40 5b [2] 57 50 [2] 4c 1e [2] 71 }

  condition:
    any of them
}
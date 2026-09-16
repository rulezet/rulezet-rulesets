rule TTP_XOR_MULT_DOSStub_503e {
  strings:
    $key_503e = { 04 56 [2] 70 4e [2] 37 4c [2] 70 5d [2] 3e 51 [2] 32 5b [2] 25 50 [2] 3e 1e [2] 03 }

  condition:
    any of them
}
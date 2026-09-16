rule TTP_XOR_MULT_DOSStub_107e {
  strings:
    $key_107e = { 44 16 [2] 30 0e [2] 77 0c [2] 30 1d [2] 7e 11 [2] 72 1b [2] 65 10 [2] 7e 5e [2] 43 }

  condition:
    any of them
}
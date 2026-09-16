rule TTP_XOR_MULT_DOSStub_157e {
  strings:
    $key_157e = { 41 16 [2] 35 0e [2] 72 0c [2] 35 1d [2] 7b 11 [2] 77 1b [2] 60 10 [2] 7b 5e [2] 46 }

  condition:
    any of them
}
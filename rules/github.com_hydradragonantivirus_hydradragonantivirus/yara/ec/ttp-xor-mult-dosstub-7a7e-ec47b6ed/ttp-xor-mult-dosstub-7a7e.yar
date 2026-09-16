rule TTP_XOR_MULT_DOSStub_7a7e {
  strings:
    $key_7a7e = { 2e 16 [2] 5a 0e [2] 1d 0c [2] 5a 1d [2] 14 11 [2] 18 1b [2] 0f 10 [2] 14 5e [2] 29 }

  condition:
    any of them
}
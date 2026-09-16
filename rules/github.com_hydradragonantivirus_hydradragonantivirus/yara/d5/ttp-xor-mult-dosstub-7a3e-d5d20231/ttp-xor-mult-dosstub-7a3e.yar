rule TTP_XOR_MULT_DOSStub_7a3e {
  strings:
    $key_7a3e = { 2e 56 [2] 5a 4e [2] 1d 4c [2] 5a 5d [2] 14 51 [2] 18 5b [2] 0f 50 [2] 14 1e [2] 29 }

  condition:
    any of them
}
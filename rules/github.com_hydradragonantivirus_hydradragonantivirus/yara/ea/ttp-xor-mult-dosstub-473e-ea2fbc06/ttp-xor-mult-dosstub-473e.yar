rule TTP_XOR_MULT_DOSStub_473e {
  strings:
    $key_473e = { 13 56 [2] 67 4e [2] 20 4c [2] 67 5d [2] 29 51 [2] 25 5b [2] 32 50 [2] 29 1e [2] 14 }

  condition:
    any of them
}
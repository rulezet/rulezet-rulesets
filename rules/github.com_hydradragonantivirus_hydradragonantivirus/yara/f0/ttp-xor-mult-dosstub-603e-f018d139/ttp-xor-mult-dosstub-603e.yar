rule TTP_XOR_MULT_DOSStub_603e {
  strings:
    $key_603e = { 34 56 [2] 40 4e [2] 07 4c [2] 40 5d [2] 0e 51 [2] 02 5b [2] 15 50 [2] 0e 1e [2] 33 }

  condition:
    any of them
}
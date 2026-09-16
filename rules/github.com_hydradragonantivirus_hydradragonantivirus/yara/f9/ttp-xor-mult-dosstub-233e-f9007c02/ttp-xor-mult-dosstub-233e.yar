rule TTP_XOR_MULT_DOSStub_233e {
  strings:
    $key_233e = { 77 56 [2] 03 4e [2] 44 4c [2] 03 5d [2] 4d 51 [2] 41 5b [2] 56 50 [2] 4d 1e [2] 70 }

  condition:
    any of them
}
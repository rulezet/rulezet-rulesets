rule TTP_XOR_MULT_DOSStub_577e {
  strings:
    $key_577e = { 03 16 [2] 77 0e [2] 30 0c [2] 77 1d [2] 39 11 [2] 35 1b [2] 22 10 [2] 39 5e [2] 04 }

  condition:
    any of them
}
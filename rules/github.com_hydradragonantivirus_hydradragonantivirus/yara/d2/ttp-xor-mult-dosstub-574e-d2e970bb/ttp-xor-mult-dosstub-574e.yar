rule TTP_XOR_MULT_DOSStub_574e {
  strings:
    $key_574e = { 03 26 [2] 77 3e [2] 30 3c [2] 77 2d [2] 39 21 [2] 35 2b [2] 22 20 [2] 39 6e [2] 04 }

  condition:
    any of them
}
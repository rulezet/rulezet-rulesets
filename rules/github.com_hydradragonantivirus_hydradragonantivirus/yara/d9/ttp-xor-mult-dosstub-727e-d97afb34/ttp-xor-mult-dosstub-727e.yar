rule TTP_XOR_MULT_DOSStub_727e {
  strings:
    $key_727e = { 26 16 [2] 52 0e [2] 15 0c [2] 52 1d [2] 1c 11 [2] 10 1b [2] 07 10 [2] 1c 5e [2] 21 }

  condition:
    any of them
}
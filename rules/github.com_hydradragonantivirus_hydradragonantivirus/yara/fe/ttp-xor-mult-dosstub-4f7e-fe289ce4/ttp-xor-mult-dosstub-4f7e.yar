rule TTP_XOR_MULT_DOSStub_4f7e {
  strings:
    $key_4f7e = { 1b 16 [2] 6f 0e [2] 28 0c [2] 6f 1d [2] 21 11 [2] 2d 1b [2] 3a 10 [2] 21 5e [2] 1c }

  condition:
    any of them
}
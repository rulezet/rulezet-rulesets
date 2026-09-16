rule TTP_XOR_MULT_DOSStub_6e7e {
  strings:
    $key_6e7e = { 3a 16 [2] 4e 0e [2] 09 0c [2] 4e 1d [2] 00 11 [2] 0c 1b [2] 1b 10 [2] 00 5e [2] 3d }

  condition:
    any of them
}
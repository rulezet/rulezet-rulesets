rule TTP_XOR_MULT_DOSStub_1d7e {
  strings:
    $key_1d7e = { 49 16 [2] 3d 0e [2] 7a 0c [2] 3d 1d [2] 73 11 [2] 7f 1b [2] 68 10 [2] 73 5e [2] 4e }

  condition:
    any of them
}
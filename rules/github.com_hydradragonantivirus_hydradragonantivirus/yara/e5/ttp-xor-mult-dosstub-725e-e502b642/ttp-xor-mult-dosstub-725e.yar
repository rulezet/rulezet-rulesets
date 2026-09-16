rule TTP_XOR_MULT_DOSStub_725e {
  strings:
    $key_725e = { 26 36 [2] 52 2e [2] 15 2c [2] 52 3d [2] 1c 31 [2] 10 3b [2] 07 30 [2] 1c 7e [2] 21 }

  condition:
    any of them
}
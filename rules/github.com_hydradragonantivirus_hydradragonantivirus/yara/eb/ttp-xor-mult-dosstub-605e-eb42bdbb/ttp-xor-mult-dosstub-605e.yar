rule TTP_XOR_MULT_DOSStub_605e {
  strings:
    $key_605e = { 34 36 [2] 40 2e [2] 07 2c [2] 40 3d [2] 0e 31 [2] 02 3b [2] 15 30 [2] 0e 7e [2] 33 }

  condition:
    any of them
}
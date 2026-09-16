rule TTP_XOR_MULT_DOSStub_6c5e {
  strings:
    $key_6c5e = { 38 36 [2] 4c 2e [2] 0b 2c [2] 4c 3d [2] 02 31 [2] 0e 3b [2] 19 30 [2] 02 7e [2] 3f }

  condition:
    any of them
}
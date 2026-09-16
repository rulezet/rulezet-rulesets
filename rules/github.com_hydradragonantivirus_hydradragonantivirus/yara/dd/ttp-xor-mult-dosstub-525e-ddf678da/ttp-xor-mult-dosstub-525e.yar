rule TTP_XOR_MULT_DOSStub_525e {
  strings:
    $key_525e = { 06 36 [2] 72 2e [2] 35 2c [2] 72 3d [2] 3c 31 [2] 30 3b [2] 27 30 [2] 3c 7e [2] 01 }

  condition:
    any of them
}
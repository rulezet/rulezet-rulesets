rule TTP_XOR_MULT_DOSStub_415e {
  strings:
    $key_415e = { 15 36 [2] 61 2e [2] 26 2c [2] 61 3d [2] 2f 31 [2] 23 3b [2] 34 30 [2] 2f 7e [2] 12 }

  condition:
    any of them
}
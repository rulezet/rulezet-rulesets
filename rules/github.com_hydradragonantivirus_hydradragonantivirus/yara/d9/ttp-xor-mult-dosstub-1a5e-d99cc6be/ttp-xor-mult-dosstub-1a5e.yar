rule TTP_XOR_MULT_DOSStub_1a5e {
  strings:
    $key_1a5e = { 4e 36 [2] 3a 2e [2] 7d 2c [2] 3a 3d [2] 74 31 [2] 78 3b [2] 6f 30 [2] 74 7e [2] 49 }

  condition:
    any of them
}
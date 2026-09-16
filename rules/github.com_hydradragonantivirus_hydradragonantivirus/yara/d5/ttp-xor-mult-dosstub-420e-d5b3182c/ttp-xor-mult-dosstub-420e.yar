rule TTP_XOR_MULT_DOSStub_420e {
  strings:
    $key_420e = { 16 66 [2] 62 7e [2] 25 7c [2] 62 6d [2] 2c 61 [2] 20 6b [2] 37 60 [2] 2c 2e [2] 11 }

  condition:
    any of them
}
rule TTP_XOR_MULT_DOSStub_595e {
  strings:
    $key_595e = { 0d 36 [2] 79 2e [2] 3e 2c [2] 79 3d [2] 37 31 [2] 3b 3b [2] 2c 30 [2] 37 7e [2] 0a }

  condition:
    any of them
}
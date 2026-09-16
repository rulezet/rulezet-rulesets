rule TTP_XOR_MULT_DOSStub_655e {
  strings:
    $key_655e = { 31 36 [2] 45 2e [2] 02 2c [2] 45 3d [2] 0b 31 [2] 07 3b [2] 10 30 [2] 0b 7e [2] 36 }

  condition:
    any of them
}
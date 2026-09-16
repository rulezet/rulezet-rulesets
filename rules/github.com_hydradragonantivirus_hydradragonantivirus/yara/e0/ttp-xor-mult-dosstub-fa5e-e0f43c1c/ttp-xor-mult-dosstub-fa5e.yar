rule TTP_XOR_MULT_DOSStub_fa5e {
  strings:
    $key_fa5e = { ae 36 [2] da 2e [2] 9d 2c [2] da 3d [2] 94 31 [2] 98 3b [2] 8f 30 [2] 94 7e [2] a9 }

  condition:
    any of them
}
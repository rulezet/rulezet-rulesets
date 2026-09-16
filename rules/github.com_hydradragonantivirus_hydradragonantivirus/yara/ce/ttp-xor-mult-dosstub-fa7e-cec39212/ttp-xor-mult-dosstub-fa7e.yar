rule TTP_XOR_MULT_DOSStub_fa7e {
  strings:
    $key_fa7e = { ae 16 [2] da 0e [2] 9d 0c [2] da 1d [2] 94 11 [2] 98 1b [2] 8f 10 [2] 94 5e [2] a9 }

  condition:
    any of them
}
rule TTP_XOR_MULT_DOSStub_fa6e {
  strings:
    $key_fa6e = { ae 06 [2] da 1e [2] 9d 1c [2] da 0d [2] 94 01 [2] 98 0b [2] 8f 00 [2] 94 4e [2] a9 }

  condition:
    any of them
}
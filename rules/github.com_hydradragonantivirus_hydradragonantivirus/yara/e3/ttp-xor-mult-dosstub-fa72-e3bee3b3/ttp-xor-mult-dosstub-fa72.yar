rule TTP_XOR_MULT_DOSStub_fa72 {
  strings:
    $key_fa72 = { ae 1a [2] da 02 [2] 9d 00 [2] da 11 [2] 94 1d [2] 98 17 [2] 8f 1c [2] 94 52 [2] a9 }

  condition:
    any of them
}
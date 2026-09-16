rule TTP_XOR_MULT_DOSStub_fa63 {
  strings:
    $key_fa63 = { ae 0b [2] da 13 [2] 9d 11 [2] da 00 [2] 94 0c [2] 98 06 [2] 8f 0d [2] 94 43 [2] a9 }

  condition:
    any of them
}
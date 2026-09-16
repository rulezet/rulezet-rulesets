rule TTP_XOR_MULT_DOSStub_fa40 {
  strings:
    $key_fa40 = { ae 28 [2] da 30 [2] 9d 32 [2] da 23 [2] 94 2f [2] 98 25 [2] 8f 2e [2] 94 60 [2] a9 }

  condition:
    any of them
}
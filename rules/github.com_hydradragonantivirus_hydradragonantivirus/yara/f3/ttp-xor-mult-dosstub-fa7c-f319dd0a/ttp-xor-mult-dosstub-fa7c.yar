rule TTP_XOR_MULT_DOSStub_fa7c {
  strings:
    $key_fa7c = { ae 14 [2] da 0c [2] 9d 0e [2] da 1f [2] 94 13 [2] 98 19 [2] 8f 12 [2] 94 5c [2] a9 }

  condition:
    any of them
}
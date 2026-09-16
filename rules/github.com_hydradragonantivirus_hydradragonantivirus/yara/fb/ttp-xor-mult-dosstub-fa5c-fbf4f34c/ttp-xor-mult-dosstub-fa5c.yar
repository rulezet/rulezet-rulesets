rule TTP_XOR_MULT_DOSStub_fa5c {
  strings:
    $key_fa5c = { ae 34 [2] da 2c [2] 9d 2e [2] da 3f [2] 94 33 [2] 98 39 [2] 8f 32 [2] 94 7c [2] a9 }

  condition:
    any of them
}
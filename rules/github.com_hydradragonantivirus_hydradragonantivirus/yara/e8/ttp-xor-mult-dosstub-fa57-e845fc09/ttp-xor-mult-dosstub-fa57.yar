rule TTP_XOR_MULT_DOSStub_fa57 {
  strings:
    $key_fa57 = { ae 3f [2] da 27 [2] 9d 25 [2] da 34 [2] 94 38 [2] 98 32 [2] 8f 39 [2] 94 77 [2] a9 }

  condition:
    any of them
}
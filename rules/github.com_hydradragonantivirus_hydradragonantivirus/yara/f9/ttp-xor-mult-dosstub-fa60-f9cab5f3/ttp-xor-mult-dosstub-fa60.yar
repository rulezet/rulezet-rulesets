rule TTP_XOR_MULT_DOSStub_fa60 {
  strings:
    $key_fa60 = { ae 08 [2] da 10 [2] 9d 12 [2] da 03 [2] 94 0f [2] 98 05 [2] 8f 0e [2] 94 40 [2] a9 }

  condition:
    any of them
}
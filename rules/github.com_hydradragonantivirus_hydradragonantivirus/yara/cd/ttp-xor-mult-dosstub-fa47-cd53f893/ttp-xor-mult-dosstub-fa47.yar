rule TTP_XOR_MULT_DOSStub_fa47 {
  strings:
    $key_fa47 = { ae 2f [2] da 37 [2] 9d 35 [2] da 24 [2] 94 28 [2] 98 22 [2] 8f 29 [2] 94 67 [2] a9 }

  condition:
    any of them
}
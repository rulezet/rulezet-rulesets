rule TTP_XOR_MULT_DOSStub_fa20 {
  strings:
    $key_fa20 = { ae 48 [2] da 50 [2] 9d 52 [2] da 43 [2] 94 4f [2] 98 45 [2] 8f 4e [2] 94 00 [2] a9 }

  condition:
    any of them
}
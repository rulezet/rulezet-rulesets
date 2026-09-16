rule TTP_XOR_MULT_DOSStub_fa77 {
  strings:
    $key_fa77 = { ae 1f [2] da 07 [2] 9d 05 [2] da 14 [2] 94 18 [2] 98 12 [2] 8f 19 [2] 94 57 [2] a9 }

  condition:
    any of them
}
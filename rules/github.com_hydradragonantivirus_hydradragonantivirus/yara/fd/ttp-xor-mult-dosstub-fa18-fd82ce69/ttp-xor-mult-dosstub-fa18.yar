rule TTP_XOR_MULT_DOSStub_fa18 {
  strings:
    $key_fa18 = { ae 70 [2] da 68 [2] 9d 6a [2] da 7b [2] 94 77 [2] 98 7d [2] 8f 76 [2] 94 38 [2] a9 }

  condition:
    any of them
}
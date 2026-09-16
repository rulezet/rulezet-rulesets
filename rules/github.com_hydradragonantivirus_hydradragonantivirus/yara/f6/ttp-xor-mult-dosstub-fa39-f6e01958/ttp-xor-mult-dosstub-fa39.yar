rule TTP_XOR_MULT_DOSStub_fa39 {
  strings:
    $key_fa39 = { ae 51 [2] da 49 [2] 9d 4b [2] da 5a [2] 94 56 [2] 98 5c [2] 8f 57 [2] 94 19 [2] a9 }

  condition:
    any of them
}
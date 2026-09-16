rule TTP_XOR_MULT_DOSStub_fa38 {
  strings:
    $key_fa38 = { ae 50 [2] da 48 [2] 9d 4a [2] da 5b [2] 94 57 [2] 98 5d [2] 8f 56 [2] 94 18 [2] a9 }

  condition:
    any of them
}
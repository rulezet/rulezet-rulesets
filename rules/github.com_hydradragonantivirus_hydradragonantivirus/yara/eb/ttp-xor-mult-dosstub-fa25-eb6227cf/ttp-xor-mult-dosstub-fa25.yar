rule TTP_XOR_MULT_DOSStub_fa25 {
  strings:
    $key_fa25 = { ae 4d [2] da 55 [2] 9d 57 [2] da 46 [2] 94 4a [2] 98 40 [2] 8f 4b [2] 94 05 [2] a9 }

  condition:
    any of them
}
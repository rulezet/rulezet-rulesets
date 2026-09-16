rule TTP_XOR_MULT_DOSStub_fae6 {
  strings:
    $key_fae6 = { ae 8e [2] da 96 [2] 9d 94 [2] da 85 [2] 94 89 [2] 98 83 [2] 8f 88 [2] 94 c6 [2] a9 }

  condition:
    any of them
}
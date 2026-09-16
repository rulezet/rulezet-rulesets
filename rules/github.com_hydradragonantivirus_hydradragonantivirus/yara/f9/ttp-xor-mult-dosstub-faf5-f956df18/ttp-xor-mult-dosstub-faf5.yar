rule TTP_XOR_MULT_DOSStub_faf5 {
  strings:
    $key_faf5 = { ae 9d [2] da 85 [2] 9d 87 [2] da 96 [2] 94 9a [2] 98 90 [2] 8f 9b [2] 94 d5 [2] a9 }

  condition:
    any of them
}
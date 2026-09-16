rule TTP_XOR_MULT_DOSStub_fae3 {
  strings:
    $key_fae3 = { ae 8b [2] da 93 [2] 9d 91 [2] da 80 [2] 94 8c [2] 98 86 [2] 8f 8d [2] 94 c3 [2] a9 }

  condition:
    any of them
}
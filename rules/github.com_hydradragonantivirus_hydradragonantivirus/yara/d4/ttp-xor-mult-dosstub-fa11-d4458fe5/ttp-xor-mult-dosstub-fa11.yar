rule TTP_XOR_MULT_DOSStub_fa11 {
  strings:
    $key_fa11 = { ae 79 [2] da 61 [2] 9d 63 [2] da 72 [2] 94 7e [2] 98 74 [2] 8f 7f [2] 94 31 [2] a9 }

  condition:
    any of them
}
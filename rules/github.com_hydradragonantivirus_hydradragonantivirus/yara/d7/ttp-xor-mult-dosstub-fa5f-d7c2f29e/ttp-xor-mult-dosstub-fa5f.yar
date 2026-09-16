rule TTP_XOR_MULT_DOSStub_fa5f {
  strings:
    $key_fa5f = { ae 37 [2] da 2f [2] 9d 2d [2] da 3c [2] 94 30 [2] 98 3a [2] 8f 31 [2] 94 7f [2] a9 }

  condition:
    any of them
}
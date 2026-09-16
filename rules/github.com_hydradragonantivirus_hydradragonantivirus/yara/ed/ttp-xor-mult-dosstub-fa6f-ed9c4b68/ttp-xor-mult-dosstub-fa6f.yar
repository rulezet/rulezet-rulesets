rule TTP_XOR_MULT_DOSStub_fa6f {
  strings:
    $key_fa6f = { ae 07 [2] da 1f [2] 9d 1d [2] da 0c [2] 94 00 [2] 98 0a [2] 8f 01 [2] 94 4f [2] a9 }

  condition:
    any of them
}
rule TTP_XOR_MULT_DOSStub_fa4a {
  strings:
    $key_fa4a = { ae 22 [2] da 3a [2] 9d 38 [2] da 29 [2] 94 25 [2] 98 2f [2] 8f 24 [2] 94 6a [2] a9 }

  condition:
    any of them
}
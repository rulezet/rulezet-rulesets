rule TTP_XOR_MULT_DOSStub_fa2f {
  strings:
    $key_fa2f = { ae 47 [2] da 5f [2] 9d 5d [2] da 4c [2] 94 40 [2] 98 4a [2] 8f 41 [2] 94 0f [2] a9 }

  condition:
    any of them
}
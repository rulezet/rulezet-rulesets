rule TTP_XOR_MULT_DOSStub_fa45 {
  strings:
    $key_fa45 = { ae 2d [2] da 35 [2] 9d 37 [2] da 26 [2] 94 2a [2] 98 20 [2] 8f 2b [2] 94 65 [2] a9 }

  condition:
    any of them
}
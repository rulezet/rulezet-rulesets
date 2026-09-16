rule TTP_XOR_MULT_DOSStub_fa10 {
  strings:
    $key_fa10 = { ae 78 [2] da 60 [2] 9d 62 [2] da 73 [2] 94 7f [2] 98 75 [2] 8f 7e [2] 94 30 [2] a9 }

  condition:
    any of them
}
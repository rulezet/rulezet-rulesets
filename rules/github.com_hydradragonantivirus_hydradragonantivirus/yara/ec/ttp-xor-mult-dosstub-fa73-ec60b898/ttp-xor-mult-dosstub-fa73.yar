rule TTP_XOR_MULT_DOSStub_fa73 {
  strings:
    $key_fa73 = { ae 1b [2] da 03 [2] 9d 01 [2] da 10 [2] 94 1c [2] 98 16 [2] 8f 1d [2] 94 53 [2] a9 }

  condition:
    any of them
}
rule TTP_XOR_MULT_DOSStub_fa67 {
  strings:
    $key_fa67 = { ae 0f [2] da 17 [2] 9d 15 [2] da 04 [2] 94 08 [2] 98 02 [2] 8f 09 [2] 94 47 [2] a9 }

  condition:
    any of them
}
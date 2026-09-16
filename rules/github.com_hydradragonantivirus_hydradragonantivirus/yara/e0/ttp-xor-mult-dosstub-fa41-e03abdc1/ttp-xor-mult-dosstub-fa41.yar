rule TTP_XOR_MULT_DOSStub_fa41 {
  strings:
    $key_fa41 = { ae 29 [2] da 31 [2] 9d 33 [2] da 22 [2] 94 2e [2] 98 24 [2] 8f 2f [2] 94 61 [2] a9 }

  condition:
    any of them
}